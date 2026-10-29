variable "zone_name" {
  description = "Zone that already exists in the account (e.g. aedis.build). The module never creates or deletes the zone."
  type        = string
}

variable "plan" {
  description = "Plan of the zone: free or pro. Sets the rule limits, the rate limiting rules and the managed rulesets."
  type        = string
  default     = "free"

  validation {
    condition     = contains(["free", "pro"], var.plan)
    error_message = "plan must be free or pro."
  }
}

variable "form_requests_per_period" {
  description = "POSTs per IP accepted on the forms of the workloads in each period (10 s on free, 60 s on pro)."
  type        = number
  default     = 3
}

variable "site_requests_per_period" {
  description = <<-EOT
    General limit: requests per IP every 10 s on the hostnames of the workloads that are not cdn (every path and method,
    verified bots excluded). It is the free plan's rule when no workload has forms; on pro it always applies. 100 = 10
    req/s sustained, room for the first load of a page (HTML, chunks, CSS, fonts, images and link prefetch) and for
    several visitors behind the same NAT.
  EOT
  type        = number
  default     = 100
}

variable "rate_limit_action" {
  description = "Rate limiting action: managed_challenge (people pass the challenge) or block. Unset, it is managed_challenge on pro and block on free, the only action Free accepts in rate limiting."
  type        = string
  default     = null

  validation {
    condition     = contains(["managed_challenge", "block"], coalesce(var.rate_limit_action, "block"))
    error_message = "rate_limit_action must be managed_challenge or block."
  }
}

variable "bot_fight_mode" {
  description = "Bot Fight Mode on free (Super Bot Fight Mode replaces it on pro). It takes no exceptions: see its cost in the README."
  type        = bool
  default     = true
}

variable "ai_bots" {
  description = <<-EOT
    AI policy by behavior (allow, block or only_on_ad_pages): search, agent (agents and chat acting for a person) and
    training (model training, including mixed search and training crawlers). labyrinth turns on AI Labyrinth (decoy
    links for crawlers that ignore robots.txt).
  EOT
  type = object({
    search    = optional(string, "allow")
    agent     = optional(string, "allow")
    training  = optional(string, "block")
    labyrinth = optional(bool, false)
  })
  default = {}

  validation {
    condition     = alltrue([for p in [var.ai_bots.search, var.ai_bots.agent, var.ai_bots.training] : contains(["allow", "block", "only_on_ad_pages"], p)])
    error_message = "each ai_bots policy is allow, block or only_on_ad_pages."
  }
}

variable "custom_rules" {
  description = "WAF rules for the whole zone (a site's own rules go in workloads[*].rules); the zone's total respects the plan (5 on free, 20 on pro)."
  type = list(object({
    description = string
    expression  = string
    action      = string
    ref         = optional(string)
  }))
  default = []
}

variable "email_routing" {
  description = <<-EOT
    Email Routing of the zone; null = off. addresses: verified destinations (each one gets a verification email; a
    Worker's send_email binding only sends to them). rules: zone address to a Worker or forwarded.
  EOT
  type = object({
    addresses = list(string)
    rules = optional(list(object({
      to      = string
      worker  = optional(string)
      forward = optional(list(string))
    })), [])
  })
  default = null

  validation {
    condition     = var.email_routing == null || alltrue([for r in try(var.email_routing.rules, []) : (r.worker == null) != (r.forward == null)])
    error_message = "each email_routing rule has worker or forward, never both."
  }
}

variable "r2_buckets" {
  description = "R2 buckets of the account used by the sites (e.g. uploads), besides the cdn buckets; [] = none."
  type        = list(string)
  default     = []
}

variable "workloads" {
  description = <<-EOT
    Intent of each site or API of the zone, one key per workload; the same structure feeds the module of another
    provider. The module creates no Worker and no Worker domain: Wrangler and the deploy pipeline own them.
      type        site-static (GET and HEAD), site-ssr (plus POST), api (plus PUT, PATCH, DELETE and OPTIONS) or cdn
                  (R2 bucket served on a custom domain, GET and HEAD)
      hostnames   the workload's hostnames; every generated rule is scoped to them
      forms       paths that receive POST (rate limiting); site-ssr and api only
      turnstile   a Turnstile widget for the hostnames; not for cdn
      headers     response headers (on a cdn, they override or add to the default security headers)
      rules       WAF rules of this workload only (the expression is combined with the hostnames)
      bucket, allowed_referers, manage_domain   cdn only: R2 bucket, domains whose Referer passes the hotlink rule and
                  whether Terraform owns the R2 custom domain (the provider cannot import it)
  EOT
  type = map(object({
    type      = string
    hostnames = list(string)
    forms     = optional(list(string), [])
    turnstile = optional(bool, false)
    headers   = optional(map(string), {})
    rules = optional(list(object({
      description = string
      expression  = string
      action      = string
      ref         = optional(string)
    })), [])
    bucket           = optional(string)
    allowed_referers = optional(list(string), [])
    manage_domain    = optional(bool, true)
  }))
  default = {}

  validation {
    condition     = alltrue([for w in values(var.workloads) : contains(["site-static", "site-ssr", "api", "cdn"], w.type) && length(w.hostnames) > 0])
    error_message = "each workload has type site-static, site-ssr, api or cdn and at least one hostname."
  }

  validation {
    condition     = length(flatten([for w in values(var.workloads) : w.hostnames])) == length(distinct(flatten([for w in values(var.workloads) : w.hostnames])))
    error_message = "a hostname belongs to a single workload."
  }

  validation {
    condition     = alltrue([for w in values(var.workloads) : (length(w.forms) == 0 || contains(["site-ssr", "api"], w.type)) && alltrue([for p in w.forms : startswith(p, "/")])])
    error_message = "forms only on site-ssr or api workloads (a static export and a cdn take no POST), and each path starts with /."
  }

  validation {
    condition     = alltrue([for w in values(var.workloads) : w.type == "cdn" ? (w.bucket != null && !w.turnstile) : (w.bucket == null && length(w.allowed_referers) == 0)])
    error_message = "a cdn workload needs a bucket and has no turnstile; bucket and allowed_referers are for cdn only."
  }

  validation {
    condition     = alltrue(flatten([for w in values(var.workloads) : [for d in w.allowed_referers : can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)+$", d))]]))
    error_message = "allowed_referers are domains (e.g. aedis.build), with no scheme, path or wildcard."
  }
}
