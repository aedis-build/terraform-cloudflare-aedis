# Reference of every module variable, in a fictitious zone (example.com) on the Pro plan with several workloads. Each
# block says what changes on Free. Nothing here belongs to a real zone: change names, hostnames and addresses first.
terraform {
  required_version = ">= 1.7"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.28.1"
    }
  }
}

# Token in CLOUDFLARE_API_TOKEN (scopes in the module README); never in code.
provider "cloudflare" {}

variable "origin_verify" {
  description = "Value of the API's verification header; kept in terraform.tfvars or TF_VAR_origin_verify, out of git."
  type        = string
  sensitive   = true
}

module "zone" {
  # Outside this repository: source = "aedis-build/aedis/cloudflare" and version = "<exact release, e.g. 1.0.0>".
  source = "../.."

  zone_name = "example.com"

  # Free: 5 custom rules in the zone instead of 20, 1 rate limiting rule instead of 2, Bot Fight Mode instead of Super
  # Bot Fight Mode and no configurable managed ruleset (the Free Managed Ruleset runs by itself).
  plan = "pro"

  # The intent of each site, API and CDN. Rule ceilings belong to the zone: every workload shares the same 20 (5 on
  # Free). Here: methods 1 (one rule for every type) + cdn hotlink 1 + the app's rules 1 + custom_rules 1 = 4, which
  # also fits Free; the plan says who uses what when the total goes over the ceiling.
  workloads = {
    site = {
      type      = "site-ssr"
      hostnames = ["example.com", "www.example.com"]
      forms     = ["/api/contato"]
      turnstile = true
    }
    app = {
      type      = "site-ssr"
      hostnames = ["app.example.com"]
      forms     = ["/api/convites"]
      rules = [{
        description = "Admin only from Brazil"
        expression  = "starts_with(http.request.uri.path, \"/admin\") and ip.src.country ne \"BR\""
        action      = "block"
      }]
    }
    # API behind Cloudflare; the header comes from a sensitive variable, never from a secret written here.
    api = {
      type      = "api"
      hostnames = ["api.example.com"]
      headers   = { "X-Origin-Verify" = var.origin_verify }
    }
    cdn = {
      type             = "cdn"
      hostnames        = ["cdn.example.com"]
      bucket           = "example-cdn"
      allowed_referers = ["example.com"]
      headers          = { "Timing-Allow-Origin" = "https://example.com" }
      manage_domain    = true
    }
  }

  # Rate limiting per IP. The forms of site and app go in a single rule, with the hosts and paths of each. Free: a
  # 10 s window, and this becomes the only rule (the general limit goes away); Pro: a 1 minute window, next to the
  # general limit. Thresholds belong to the zone because, on Free, every workload fits in one rule.
  form_requests_per_period = 3

  # General limit per IP every 10 s on sites and APIs (the cdn stays out), without verified bots. Free: only exists
  # when no workload has forms.
  site_requests_per_period = 100

  # managed_challenge requires mitigation_timeout 0 on Free, Pro and Business (the module does that). With block, the
  # action lasts one period: 10 s on Free, 60 s for the forms on Pro.
  rate_limit_action = "managed_challenge"

  # Free: turns on Bot Fight Mode, which takes no exceptions (monitors may get challenged) and injects a script that a
  # static site's hash-based CSP blocks. Pro: ignored; the module turns Bot Fight Mode off and Super Bot Fight Mode on.
  bot_fight_mode = true

  # Same on both plans: search and agents allowed, training blocked, AI Labyrinth off.
  ai_bots = {
    search    = "allow"
    agent     = "allow"
    training  = "block"
    labyrinth = false
  }

  # Rules for the whole zone (a workload's own rules go in workloads[*].rules). They count toward the same ceiling.
  custom_rules = [{
    description = "Probes for files no site has"
    expression  = "http.request.uri.path in {\"/wp-login.php\" \"/xmlrpc.php\" \"/.env\"}"
    action      = "block"
  }]

  # Same on both plans. Each destination gets a verification email; the Worker's send_email only sends to them.
  email_routing = {
    addresses = ["propostas@example.com"]
    rules     = [{ to = "contato@example.com", worker = "example-site" }]
  }

  # Same on both plans: account buckets besides the cdn ones, with the r2.dev dev URL turned off.
  r2_buckets = ["example-uploads"]
}

output "turnstile_sitekeys" {
  value = module.zone.turnstile_sitekeys
}

output "turnstile_secrets" {
  value     = module.zone.turnstile_secrets
  sensitive = true
}
