output "zone_id" {
  description = "ID of the zone."
  value       = local.zone_id
}

output "account_id" {
  description = "ID of the account that owns the zone."
  value       = local.account_id
}

output "turnstile_sitekeys" {
  description = "Public Turnstile sitekey per workload (goes in the form's HTML)."
  value       = { for k, w in cloudflare_turnstile_widget.this : k => w.sitekey }
}

output "turnstile_secrets" {
  description = "Turnstile secret per workload, for the Worker's siteverify: it goes to the Worker's runtime secrets, never to git."
  value       = { for k, w in cloudflare_turnstile_widget.this : k => w.secret }
  sensitive   = true
}
