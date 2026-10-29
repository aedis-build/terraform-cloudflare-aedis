# rlfn.studio: Next SSR (OpenNext) with the proposals form at /api/proposals, Turnstile on the form and the Worker's
# send_email binding delivering proposals to a verified Email Routing address. Free plan.
terraform {
  required_version = ">= 1.6"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.28.1"
    }
  }
}

# Token in CLOUDFLARE_API_TOKEN (scopes in the module README); never in code.
provider "cloudflare" {}

variable "proposals_inbox" {
  description = "Inbox that receives the proposals (verified send_email destination); kept in terraform.tfvars, out of git."
  type        = string
}

module "zone" {
  # Outside this repository: source = "aedis-build/aedis/cloudflare" and version = "<exact release, e.g. 1.0.0>".
  source = "../.."

  zone_name = "rlfn.studio"
  plan      = "free"

  workloads = {
    site = {
      type      = "site-ssr"
      hostnames = ["rlfn.studio", "staging.rlfn.studio"]
      forms     = ["/api/proposals"]
      turnstile = true
    }
  }

  email_routing = {
    addresses = [var.proposals_inbox]
  }
}

output "turnstile_sitekey" {
  value = module.zone.turnstile_sitekeys["site"]
}

output "turnstile_secret" {
  value     = module.zone.turnstile_secrets["site"]
  sensitive = true
}
