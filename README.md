# Aedis Cloudflare module

Terraform module (provider `cloudflare/cloudflare` v5) that applies the security posture of a Cloudflare zone serving
Aedis sites and APIs. One module per zone. Each site, API or CDN of the zone goes in `workloads` as a declaration of
intent: the same structure the Aedis module of another provider receives, with no multi-provider selector module. The
module creates no Worker and no Worker domain: Wrangler and the deploy pipeline
([aedis-platform `deploy-site.yml`](https://github.com/aedis-build/aedis-platform/blob/main/docs/sites.md)) keep owning
the script, its versions, the custom domain and the secrets.

## Usage

```hcl
module "zone" {
  source  = "aedis-build/aedis/cloudflare"
  version = "1.0.0" # an exact release; releases are immutable

  zone_name = "example.com"
  plan      = "free"
  workloads = {
    site = { type = "site-ssr", hostnames = ["example.com", "www.example.com"], forms = ["/api/contact"], turnstile = true }
    cdn  = { type = "cdn", hostnames = ["cdn.example.com"], bucket = "example-cdn", allowed_referers = ["example.com"] }
  }
}
```

The provider reads the token from `CLOUDFLARE_API_TOKEN` (scopes below). The module declares no backend: state is the
caller's choice.

Reference of every option: [`examples/complete`](examples/complete/main.tf), a fictitious zone (`example.com`, Pro
plan) with several workloads (two sites, an API and a cdn), every variable of the module and, in each block, what
changes on Free; `terraform test` plans that example with no credentials. Real zones:
[`examples/aedis-build`](examples/aedis-build/main.tf) (two static sites and a cdn) and
[`examples/rlfn-studio`](examples/rlfn-studio/main.tf) (SSR with a form, Turnstile and Email Routing).

In a site's repository the module call lives in `infra/cloudflare/main.tf`, where `aedis platform validate --level 3`
(control PLT-20, `waf-declared-prod`) checks it against every production `wrangler.jsonc`: each custom domain belongs
to the `hostnames` of a workload, `workers_dev` and `preview_urls` are off, and every POST route of the code is in that
workload's `forms`.

## Workloads

| Field | Declares | The module generates |
|---|---|---|
| `type` | `site-static`, `site-ssr`, `api` or `cdn` | the accepted methods: `GET`/`HEAD` (site-static, cdn), plus `POST` (site-ssr), plus `PUT`/`PATCH`/`DELETE`/`OPTIONS` (api); one rule for the whole zone |
| `hostnames` | the workload's hostnames; each belongs to a single workload and is in the zone | the scope of every rule, header and widget of the workload |
| `forms` | paths that receive POST (site-ssr and api only) | entries in the forms rate limiting rule, with the workload's hostnames |
| `turnstile` | `true` for a widget (not for cdn) | a `managed` widget on the hostnames; sitekey and secret in the `turnstile_sitekeys` and `turnstile_secrets` outputs, per workload |
| `headers` | response headers | a rule in the zone's single response headers ruleset, on the workload's hostnames; on a cdn they override or add to the default security headers |
| `rules` | WAF rules of this workload only | each expression becomes `(workload hostnames) and (expression)` in the zone's custom rules |
| `bucket`, `allowed_referers`, `manage_domain` | cdn only: the R2 bucket, the domains whose Referer passes the hotlink rule and whether Terraform owns the R2 custom domain | a bucket with its dev URL off, an R2 custom domain per hostname (TLS 1.2) and the hotlink rule |

What belongs to the zone stays in the zone: `plan`, `bot_fight_mode`, `ai_bots`, `email_routing`, `custom_rules` (rules
for the whole zone), `r2_buckets`, and the rate limiting thresholds and action.

### Shared zone limits

Custom and rate limiting rules belong to the **zone**, not to a site: every workload shares the same ceiling.

| | Free | Pro |
|---|---|---|
| Custom rules | 5 | 20 |
| Rate limiting rules | 1, 10 s window | 2, window up to 1 minute |

The module adds up what everyone asks for (the methods rule, 1 hotlink rule per cdn, each workload's `rules` and the
zone's `custom_rules`) and fails at plan time when the total goes over the ceiling, saying who uses what:

```
The free plan allows 5 custom rules in the zone and the configuration asks for 6:
custom_rules (zone) 1, methods (module) 1, workload cdn 1, workload site 3.
```

Rate limiting never overflows: the `forms` of every workload go in one rule, with the hosts and paths of each. On Free
it is the only rule; with no forms in any workload, the only rule is the general limit. On Pro both exist. That is why
the thresholds (`form_requests_per_period`, `site_requests_per_period`) and the action (`rate_limit_action`) belong to
the zone: on Free every workload fits in the same rule and could not have different numbers.

| Resource | Free | Pro |
|---|---|---|
| Minimum TLS 1.2, Always Use HTTPS, HSTS (2 years, subdomains, preload, nosniff) | yes | yes |
| Bot Fight Mode (`bot_fight_mode`, on by default) | yes | replaced by Super Bot Fight Mode: verified bots pass, unidentified automation gets a Managed Challenge |
| AI policy by behavior (`ai_bots`): search and agents allowed, training blocked; optional AI Labyrinth; the site's own robots.txt (not the managed one) | yes | yes |
| Rate limiting per IP, `rate_limit_action` (Managed Challenge with `mitigation_timeout = 0` by default, or Block) | 1 rule: `POST` to the `forms` of every workload (3 per 10 s) or, with no forms, a general limit on sites and APIs (100 per 10 s, without cdn and verified bots) | 2 rules: forms (3 per minute) and the general limit |
| Managed rulesets | the Free Managed Ruleset runs by itself | Cloudflare Managed + OWASP Core |
| Email Routing (verified destinations, rules to a Worker or forwarded) | when asked | when asked |
| R2 (`r2_buckets` and the cdn buckets), with the `r2.dev` dev URL turned off explicitly | when asked | when asked |
| Response headers: a single ruleset in the `http_response_headers_transform` phase | when a workload is a cdn or has `headers` | same |

### Bots and AI

Bot Fight Mode and the AI policy are separate controls: allowing AI crawlers in robots.txt (or in `ai_bots`) does not
require turning Bot Fight Mode off. The default policy allows search (`search`) and agents (`agent`) and blocks
training (`training`, which includes mixed search and training crawlers); each takes `allow`, `block` or
`only_on_ad_pages`. `ai_bots.labyrinth` turns on AI Labyrinth, which sends crawlers that ignore robots.txt to generated
pages.

Bot Fight Mode on Free has a cost:

- It takes no exceptions: no skip rule bypasses it. An uptime monitor or the deploy's smoke test may get challenged;
  prefer monitors Cloudflare recognizes as verified bots.
- It injects its JavaScript Detections script into pages. On a static site with a hash-based CSP the script has no
  hash and is blocked: it shows as a CSP error in the console and does not affect the site
  ([aedis-build/aedis.build#26](https://github.com/aedis-build/aedis.build/issues/26),
  [aedis-build/aedis-ui#239](https://github.com/aedis-build/aedis-ui/issues/239)). On an SSR site with a nonce,
  Cloudflare adds the response's nonce to the script and it runs.

Whoever does not accept that cost sets `bot_fight_mode = false`. On Pro the module turns Bot Fight Mode off and Super
Bot Fight Mode on.

### Rate limiting

The default action is Managed Challenge: people pass the challenge and the counter resets. The API requires
`mitigation_timeout = 0` with a challenge on Free, Pro and Business; with `rate_limit_action = "block"` the action
lasts one period (10 s on Free). `form_requests_per_period = 3` accepts three submissions per IP in the window (10 s on
Free, 1 minute on Pro).

The general limit (`site_requests_per_period = 100` every 10 s, 10 req/s sustained) covers every path and method on the
hostnames of sites and APIs, without the cdn workloads (GitHub's camo fetches README images from a few IPs) and without
verified bots (the search crawlers allowed). The first load of a page of a Next site makes a few dozen requests (HTML,
chunks, CSS, fonts, images and link prefetch), and several visitors behind the same NAT share an IP; 100 leaves room
for that and still catches a scraper or a flood from a single IP. On Free it only exists when no workload has `forms`,
because the plan has a single rule.

### CDN (`type = "cdn"`)

A CDN is a workload like the others: an R2 bucket served on a custom domain, with no Worker. Being in `workloads` puts
its methods rule in the same `GET`/`HEAD` term as the static sites (no extra Free rule) and its count in the same sum
of limits.

| What | How |
|---|---|
| Bucket | not duplicated when it is also in `r2_buckets`; dev URL off |
| Custom domain | one `cloudflare_r2_custom_domain` per hostname, TLS 1.2 (`manage_domain = false` leaves the domain out; see below) |
| Methods | `GET` and `HEAD`; anything else is blocked |
| Hotlink | an empty Referer passes (GitHub's camo loads README images with no Referer); a Referer `https://<domain>/…` or `https://<sub>.<domain>/…` of `allowed_referers` passes; anything else is blocked |
| Headers | `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`, `Cross-Origin-Resource-Policy: same-site`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, plus `headers` |
| Cache | out of the module: `Cache-Control` comes from each object's metadata at upload |

The hotlink rule uses the `wildcard` operator, available on every plan (`matches`, for regexes, is Business and
Enterprise only). Wildcard matches the whole URL, and the pattern requires `/` right after the host, so
`evilaedis.build` and `aedis.build.evil.com` do not pass; the module's test emulates that matching over the generated
patterns. Hotlink protection saves bandwidth, it is not access control: whoever wants to embed without permission sends
the page with no Referer (`referrerpolicy="no-referrer"`), which passes on purpose.

### Response headers

The `http_response_headers_transform` phase has **a single ruleset per zone**, and this module owns it as soon as a
workload is a cdn or has `headers`: a response header Transform Rule created in the dashboard disappears on apply.
Every response header of the zone goes through the `headers` of the workload that owns the hostname (always `set`).

A header the origin must *receive* (for example an `X-Origin-Verify` checked by a Worker) is a request header: it
belongs to the `http_request_late_transform` phase, which this module does not manage yet.

## Out of the module

| What | Who owns it | Why |
|---|---|---|
| The zone | the owner, in the dashboard | it already exists; the module only reads it (`data "cloudflare_zone"`), so a `destroy` never deletes it |
| The Worker's custom domain | `routes` with `custom_domain: true` in `wrangler.jsonc` | Wrangler creates the DNS record and the certificate on every deploy; two owners fight |
| The Worker's secrets | the deploy pipeline's runtime secrets, bound to each version | a secret bound to the version rolls back with it; the Turnstile secret goes from the `turnstile_secrets` output straight there |
| Request and URL Transform Rules, Cache Rules, DNS of other services | the dashboard or another module | outside the security posture (response headers belong to the module: the workloads' `headers`) |

## Token

An API token only for this module (*My Profile → API Tokens → Create Custom Token*), restricted to the zones and the
account in use, short-lived and with only what the requested resources use:

| Scope | Permission | For |
|---|---|---|
| Zone | Zone: Read | the `data "cloudflare_zone"` |
| Zone | Zone Settings: Edit | TLS, HTTPS, HSTS |
| Zone | Zone WAF: Edit | custom rules, rate limiting, managed rulesets |
| Zone | Transform Rules: Edit | with a cdn workload or `headers` (response headers phase) |
| Zone | Bot Management: Edit | Bot Fight Mode, AI policy, Super Bot Fight Mode |
| Zone | Email Routing Rules: Edit | with `email_routing` |
| Account | Email Routing Addresses: Edit | with `email_routing` |
| Account | Turnstile: Edit | with a workload with `turnstile = true` |
| Account | Workers R2 Storage: Edit | with `r2_buckets` or a cdn workload (bucket, dev URL and custom domain) |

It is not the deploy pipeline's token: that one publishes Workers and never touches the WAF.

## Adopting a zone that already exists

Zone settings and Bot Management are singletons: the first apply just sets them. A phase ruleset, a widget, an email
destination or rule, or a bucket created earlier in the dashboard has to enter the state with `terraform import`,
otherwise the apply fails trying to create it again:

```bash
export CLOUDFLARE_API_TOKEN=...        # the token above
ZONE_ID=...; ACCOUNT_ID=...            # zone Overview, right column
api() { curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" "https://api.cloudflare.com/client/v4$1"; }
api "/zones/$ZONE_ID/rulesets" | jq -r '.result[] | select(.kind == "zone") | "\(.phase) \(.id)"'
api "/accounts/$ACCOUNT_ID/challenges/widgets" | jq -r '.result[] | "\(.name) \(.sitekey)"'
api "/accounts/$ACCOUNT_ID/email/routing/addresses" | jq -r '.result[] | "\(.email) \(.id)"'
api "/zones/$ZONE_ID/email/routing/rules" | jq -r '.result[] | "\(.matchers[0].value // "catch-all") \(.id)"'

terraform init
terraform import 'module.zone.cloudflare_ruleset.custom[0]' "zones/$ZONE_ID/<id of the http_request_firewall_custom phase>"
terraform import 'module.zone.cloudflare_ruleset.rate_limit[0]' "zones/$ZONE_ID/<id of the http_ratelimit phase>"
terraform import 'module.zone.cloudflare_ruleset.managed[0]' "zones/$ZONE_ID/<id of the http_request_firewall_managed phase>"   # pro only
terraform import 'module.zone.cloudflare_ruleset.response_headers[0]' "zones/$ZONE_ID/<id of the http_response_headers_transform phase>"   # with a cdn or headers
terraform import 'module.zone.cloudflare_turnstile_widget.this["<workload>"]' "$ACCOUNT_ID/<sitekey>"
terraform import 'module.zone.cloudflare_email_routing_settings.this[0]' "$ZONE_ID"
terraform import 'module.zone.cloudflare_email_routing_address.this["<email>"]' "$ACCOUNT_ID/<id>"
terraform import 'module.zone.cloudflare_email_routing_rule.this["<to>"]' "$ZONE_ID/<id>"
terraform import 'module.zone.cloudflare_r2_bucket.this["<name>"]' "$ACCOUNT_ID/<name>/default"
# cloudflare_r2_managed_domain (a bucket's dev URL) cannot be imported in provider 5.28.1 and does not need to be: its
# create is a PUT that only turns off the r2.dev URL of an existing bucket.
# cloudflare_r2_custom_domain cannot be imported either, and creating a domain that already exists fails: see below.
terraform plan                          # read it: the imported rules are replaced by the module's
terraform apply
```

Import only what the listing showed. The plan after the import shows the difference between the dashboard and the
module: a hand-made rule that must stay becomes an item of `custom_rules` (zone) or of a workload's `rules`, and a
response header becomes a workload's `headers`.

**Before the first apply on an existing zone**, list the real rules of every phase the module takes over and bring
into variables everything the module does not generate. A survey from the outside (curl) does not show everything, for
example a Cache Rule or a disabled rule:

```bash
for phase in http_request_firewall_custom http_ratelimit http_response_headers_transform; do
  echo "== $phase"
  api "/zones/$ZONE_ID/rulesets/phases/$phase/entrypoint" | jq -r '.result.rules[]? | "\(.enabled) \(.action) \(.description)\n  \(.expression)"'
done
api "/accounts/$ACCOUNT_ID/r2/buckets/<bucket>/domains/custom" | jq '.result.domains'
```

### Custom domain of a CDN that already exists

Provider 5.28.1 cannot import `cloudflare_r2_custom_domain`, and creating a domain already attached to the bucket
fails. While the domain belongs to the dashboard, declare the cdn workload with `manage_domain = false`: the module
handles the rest (bucket, dev URL, rules and headers) and leaves the domain alone. For Terraform to take the domain
over, in an agreed window:

1. set `manage_domain = true` and run `terraform plan` (it should only create `cloudflare_r2_custom_domain.cdn["<hostname>"]`);
2. remove the domain from the bucket in the dashboard (R2 → bucket → Settings → Custom Domains) and run
   `terraform apply` right after. Until the certificate is issued the CDN answers with errors; images embedded in
   READMEs are broken for a few minutes.

## When the zone moves to Pro

Set `plan = "pro"` and run the plan. The Cloudflare Managed Ruleset and the OWASP Core Ruleset come in (OWASP scores
and blocks above the default threshold: watch Security Events during the first week and tune with `overrides` on a
false positive), rate limiting gets both rules (forms over 1 minute and the general limit), up to 20 custom rules fit,
and Super Bot Fight Mode replaces Bot Fight Mode: verified bots pass and unidentified automation is challenged. If the
managed phase already has a ruleset created in the dashboard, import it first (`cloudflare_ruleset.managed[0]`).

## Development

`terraform fmt -check`, `terraform validate` of the module and of every example, `terraform test` (provider mocked,
no credentials, no network to Cloudflare) and `tflint` run in `aedis-ci`. Nothing in this repository applies the
module: the owner of a zone does. Releases are cut from the Conventional Commits (`release-cut.yml`): each tag `vX.Y.Z`
is an immutable, attested GitHub Release and a version in the Terraform Registry.

## License

Apache-2.0.
