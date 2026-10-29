# aedis.build and ui.aedis.build: static sites in the same zone, with no form, plus the cdn. Free plan.
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

module "zone" {
  # Outside this repository: source = "aedis-build/aedis/cloudflare" and version = "<exact release, e.g. 1.0.0>".
  source = "../.."

  zone_name = "aedis.build"
  plan      = "free"

  # Zone rules: 1 for methods (all three entries) + 1 for the cdn's hotlink = 2 of the 5 on free. With no forms, the
  # only free rate limiting rule is the general limit per IP on both sites (the cdn stays out).
  workloads = {
    site = { type = "site-static", hostnames = ["aedis.build"] }
    ui   = { type = "site-static", hostnames = ["ui.aedis.build"] }
    # Images and static files served straight from the R2 bucket, with no Worker.
    cdn = {
      type             = "cdn"
      hostnames        = ["cdn.aedis.build"]
      bucket           = "aedis-cdn"
      allowed_referers = ["aedis.build"]
      # The domain already exists in the dashboard and the provider cannot import it: it stays out until the migration window (README).
      manage_domain = false
    }
  }
}
