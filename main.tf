# Security posture of a Cloudflare zone from the intent of each workload (site, API or CDN). The zone, the Worker, the
# Worker's custom domain (routes with custom_domain in wrangler.jsonc) and the Worker's secrets stay out of here: two
# owners of the same resource fight on every apply.

data "cloudflare_zone" "this" {
  filter = { name = var.zone_name }

  lifecycle {
    postcondition {
      condition     = alltrue([for h in flatten([for w in values(var.workloads) : w.hostnames]) : h == var.zone_name || endswith(h, ".${var.zone_name}")])
      error_message = "Every hostname in workloads must be in the zone ${var.zone_name}."
    }
  }
}

locals {
  zone_id    = data.cloudflare_zone.this.id
  account_id = data.cloudflare_zone.this.account.id
  pro        = var.plan == "pro"

  # Custom and rate limiting rules belong to the zone, not to a site: every workload shares the same ceiling.
  custom_rule_limit = local.pro ? 20 : 5

  hosts = { for k, w in var.workloads : k => "http.host in {${join(" ", [for h in w.hostnames : jsonencode(h)])}}" }

  # Methods accepted by type. One rule for the whole zone, one term per set of methods, so a workload does not spend a
  # free plan rule.
  methods = {
    "site-static" = ["GET", "HEAD"]
    "cdn"         = ["GET", "HEAD"]
    "site-ssr"    = ["GET", "HEAD", "POST"]
    "api"         = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
  }
  method_groups = {
    for set in distinct([for w in values(var.workloads) : join(" ", [for m in local.methods[w.type] : jsonencode(m)])]) :
    set => flatten([for w in values(var.workloads) : w.hostnames if join(" ", [for m in local.methods[w.type] : jsonencode(m)]) == set])
  }
  methods_rule = length(var.workloads) == 0 ? [] : [{
    ref         = "aedis_methods"
    description = "Methods accepted by workload type"
    expression  = join(" or ", [for set, hosts in local.method_groups : "(http.host in {${join(" ", [for h in hosts : jsonencode(h)])}} and not http.request.method in {${set}})"])
    action      = "block"
  }]

  # Hotlink rule of each cdn: an empty Referer passes (GitHub's camo and no-referrer pages); a Referer from an allowed
  # domain or one of its subdomains passes; anything else is blocked. The wildcard operator (every plan; matches needs
  # Business) matches the whole URL and requires "/" right after the host, so evilaedis.build and aedis.build.evil.com
  # do not pass.
  hotlink_rules = [for k, w in var.workloads : {
    ref         = "aedis_${k}_hotlink"
    description = "${k}: hotlink from another site"
    expression = join(" ", compact([
      "${local.hosts[k]} and http.referer ne \"\"",
      length(w.allowed_referers) == 0 ? "" : "and not (${join(" or ", flatten([for d in w.allowed_referers : ["http.referer wildcard \"https://${d}/*\"", "http.referer wildcard \"https://*.${d}/*\""]]))})",
    ]))
    action = "block"
  } if w.type == "cdn"]

  workload_rules = flatten([for k, w in var.workloads : [for r in w.rules : {
    ref         = coalesce(r.ref, "${k}_${md5(r.expression)}")
    description = "${k}: ${r.description}"
    expression  = "(${local.hosts[k]}) and (${r.expression})"
    action      = r.action
  }]])

  zone_rules = [for r in var.custom_rules : merge(r, { ref = coalesce(r.ref, "custom_${md5(r.expression)}") })]

  custom_rules = concat(local.methods_rule, local.hotlink_rules, local.workload_rules, local.zone_rules)

  # Who uses the custom rule ceiling, for the error message.
  custom_rule_usage = merge(
    { "methods (module)" = length(local.methods_rule) },
    { for k, w in var.workloads : "workload ${k}" => length(w.rules) + (w.type == "cdn" ? 1 : 0) },
    { "custom_rules (zone)" = length(var.custom_rules) },
  )

  # Static objects with no script or form, embedded only by pages of the same site (CORP same-site).
  cdn_default_headers = {
    "Content-Security-Policy"      = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    "Cross-Origin-Resource-Policy" = "same-site"
    "Referrer-Policy"              = "no-referrer"
    "X-Content-Type-Options"       = "nosniff"
  }

  # One ruleset per phase in a zone: the response headers of every workload live in the same one.
  response_header_rules = [for k, w in var.workloads : {
    ref               = "aedis_${k}_headers"
    description       = "${k}: response headers"
    expression        = local.hosts[k]
    action            = "rewrite"
    action_parameters = { headers = { for name, value in merge(w.type == "cdn" ? local.cdn_default_headers : {}, w.headers) : name => { operation = "set", value = value } } }
  } if w.type == "cdn" || length(w.headers) > 0]

  ai_policy = { allow = "disabled", block = "block", only_on_ad_pages = "only_on_ad_pages" }

  # Rate limiting: with a challenge, the API of Free, Pro and Business requires mitigation_timeout 0 (passing the
  # challenge resets the counter); with Block, the action lasts one period.
  challenge      = var.rate_limit_action == "managed_challenge"
  form_workloads = { for k, w in var.workloads : k => w if length(w.forms) > 0 }
  # The forms of every workload in a single rule: on free it is the zone's only rate limiting rule.
  form_rate_limit = {
    ref         = "aedis_form_rate_limit"
    description = "POST to the forms of the workloads"
    expression  = "http.request.method eq \"POST\" and (${join(" or ", [for k, w in local.form_workloads : "(${local.hosts[k]} and http.request.uri.path in {${join(" ", [for p in w.forms : jsonencode(p)])}})"])})"
    action      = var.rate_limit_action
    ratelimit = {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = local.pro ? 60 : 10
      requests_per_period = var.form_requests_per_period
      mitigation_timeout  = local.challenge ? 0 : (local.pro ? 60 : 10)
    }
  }
  # General limit per IP, without the cdn workloads (GitHub's camo fetches README images from a few IPs) and without
  # verified bots (the search crawlers the AI policy allows).
  site_hosts = flatten([for w in values(var.workloads) : w.hostnames if w.type != "cdn"])
  site_rate_limit = {
    ref         = "aedis_site_rate_limit"
    description = "Requests per IP on the hostnames of sites and APIs"
    expression  = "http.host in {${join(" ", [for h in local.site_hosts : jsonencode(h)])}} and not cf.client.bot"
    action      = var.rate_limit_action
    ratelimit = {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = 10
      requests_per_period = var.site_requests_per_period
      mitigation_timeout  = local.challenge ? 0 : 10
    }
  }
  # Free: one rule (forms, if any workload has them, otherwise the general limit). Pro: both.
  form_rules       = length(local.form_workloads) > 0 ? [local.form_rate_limit] : []
  site_rules       = length(local.site_hosts) > 0 ? [local.site_rate_limit] : []
  rate_limit_rules = local.pro ? concat(local.form_rules, local.site_rules) : slice(concat(local.form_rules, local.site_rules), 0, min(1, length(concat(local.form_rules, local.site_rules))))

  cdn_buckets = [for w in values(var.workloads) : w.bucket if w.type == "cdn"]
  cdn_domains = merge([for w in values(var.workloads) : { for h in w.hostnames : h => w.bucket } if w.type == "cdn" && w.manage_domain]...)

  # Public IDs of the managed rulesets (the same in every account).
  cloudflare_managed_ruleset = "efb7b8c949ac4650a09736fc376e9aee"
  owasp_core_ruleset         = "4814384a9e5d4991b9815dcfc25d2f1f"
}

resource "cloudflare_zone_setting" "min_tls_version" {
  zone_id    = local.zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "always_use_https" {
  zone_id    = local.zone_id
  setting_id = "always_use_https"
  value      = "on"
}

resource "cloudflare_zone_setting" "hsts" {
  zone_id    = local.zone_id
  setting_id = "security_header"
  value = {
    strict_transport_security = {
      enabled            = true
      max_age            = 63072000
      include_subdomains = true
      preload            = true
      nosniff            = true
    }
  }
}

# Bot Fight Mode and the AI policy are separate controls: allowing an AI crawler in robots.txt does not require turning
# Bot Fight Mode off. On free it challenges known bots and takes no exceptions (README: its cost for monitors and for a
# hash-based CSP). On pro Super Bot Fight Mode acts instead: verified bots pass and unidentified automation is
# challenged. The AI policy (Search, Agent, Training) applies on both plans: "allow" becomes "disabled" (no block).
resource "cloudflare_bot_management" "this" {
  zone_id                         = local.zone_id
  fight_mode                      = local.pro ? false : var.bot_fight_mode
  ai_bots_protection              = "disabled"
  aisearch                        = local.ai_policy[var.ai_bots.search]
  ai_user                         = local.ai_policy[var.ai_bots.agent]
  ai_training                     = local.ai_policy[var.ai_bots.training]
  crawler_protection              = var.ai_bots.labyrinth ? "enabled" : "disabled"
  is_robots_txt_managed           = false
  sbfm_verified_bots              = local.pro ? "allow" : null
  sbfm_definitely_automated       = local.pro ? "managed_challenge" : null
  sbfm_likely_automated           = local.pro ? "allow" : null
  sbfm_static_resource_protection = local.pro ? false : null
}

resource "cloudflare_ruleset" "custom" {
  count       = length(local.custom_rules) > 0 ? 1 : 0
  zone_id     = local.zone_id
  kind        = "zone"
  phase       = "http_request_firewall_custom"
  name        = "aedis: custom rules"
  description = "Managed by the aedis-build/aedis/cloudflare Terraform module"
  rules       = local.custom_rules

  lifecycle {
    precondition {
      condition     = length(local.custom_rules) <= local.custom_rule_limit
      error_message = "The ${var.plan} plan allows ${local.custom_rule_limit} custom rules in the zone and the configuration asks for ${length(local.custom_rules)}: ${join(", ", [for who, n in local.custom_rule_usage : "${who} ${n}" if n > 0])}."
    }
  }
}

resource "cloudflare_ruleset" "response_headers" {
  count       = length(local.response_header_rules) > 0 ? 1 : 0
  zone_id     = local.zone_id
  kind        = "zone"
  phase       = "http_response_headers_transform"
  name        = "aedis: response headers"
  description = "Managed by the aedis-build/aedis/cloudflare Terraform module"
  rules       = local.response_header_rules
}

resource "cloudflare_ruleset" "rate_limit" {
  count       = length(local.rate_limit_rules) > 0 ? 1 : 0
  zone_id     = local.zone_id
  kind        = "zone"
  phase       = "http_ratelimit"
  name        = "aedis: rate limit"
  description = "Managed by the aedis-build/aedis/cloudflare Terraform module"
  rules       = local.rate_limit_rules
}

# On free the Free Managed Ruleset already runs by itself and is not configurable; pro runs Cloudflare Managed and OWASP.
resource "cloudflare_ruleset" "managed" {
  count       = local.pro ? 1 : 0
  zone_id     = local.zone_id
  kind        = "zone"
  phase       = "http_request_firewall_managed"
  name        = "aedis: managed rulesets"
  description = "Managed by the aedis-build/aedis/cloudflare Terraform module"
  rules = [
    {
      ref               = "aedis_cloudflare_managed"
      description       = "Cloudflare Managed Ruleset"
      expression        = "true"
      action            = "execute"
      action_parameters = { id = local.cloudflare_managed_ruleset }
    },
    {
      ref               = "aedis_owasp_core"
      description       = "Cloudflare OWASP Core Ruleset"
      expression        = "true"
      action            = "execute"
      action_parameters = { id = local.owasp_core_ruleset }
    }
  ]
}

resource "cloudflare_turnstile_widget" "this" {
  for_each   = { for k, w in var.workloads : k => w if w.turnstile }
  account_id = local.account_id
  name       = "${var.zone_name} ${each.key}"
  domains    = each.value.hostnames
  mode       = "managed"
}

resource "cloudflare_email_routing_settings" "this" {
  count   = var.email_routing == null ? 0 : 1
  zone_id = local.zone_id
}

resource "cloudflare_email_routing_dns" "this" {
  count   = var.email_routing == null ? 0 : 1
  zone_id = local.zone_id
  name    = var.zone_name

  depends_on = [cloudflare_email_routing_settings.this]
}

# The addresses key the resources, and for_each refuses sensitive keys: a caller that reads the destination from a
# sensitive variable would fail the plan. An address is not a secret (it shows in the dashboard and in the address of
# the resource), so the mark is dropped here instead of in every caller.
resource "cloudflare_email_routing_address" "this" {
  for_each   = toset([for a in try(var.email_routing.addresses, []) : nonsensitive(a)])
  account_id = local.account_id
  email      = each.value
}

resource "cloudflare_email_routing_rule" "this" {
  for_each = { for r in try(var.email_routing.rules, []) : nonsensitive(r.to) => r }
  zone_id  = local.zone_id
  name     = each.key
  matchers = [{ type = "literal", field = "to", value = each.key }]
  actions = [{
    type  = each.value.worker != null ? "worker" : "forward"
    value = each.value.worker != null ? [each.value.worker] : each.value.forward
  }]

  depends_on = [cloudflare_email_routing_settings.this, cloudflare_email_routing_address.this]
}

resource "cloudflare_r2_bucket" "this" {
  for_each   = toset(concat(var.r2_buckets, local.cdn_buckets))
  account_id = local.account_id
  name       = each.value
}

# The dev URL (r2.dev) of every bucket is turned off explicitly.
resource "cloudflare_r2_managed_domain" "this" {
  for_each    = cloudflare_r2_bucket.this
  account_id  = local.account_id
  bucket_name = each.value.name
  enabled     = false
}

# Custom domain of the bucket for each cdn hostname, with TLS 1.2. The provider cannot import this resource: a domain
# that already exists in the dashboard stays out with manage_domain = false until the migration window (README).
resource "cloudflare_r2_custom_domain" "cdn" {
  for_each    = local.cdn_domains
  account_id  = local.account_id
  zone_id     = local.zone_id
  bucket_name = cloudflare_r2_bucket.this[each.value].name
  domain      = each.key
  enabled     = true
  min_tls     = "1.2"
}
