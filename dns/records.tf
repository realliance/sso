# This layer owns the sso record and the Resend sender records (resend.tf). Everything else in realliance.net is luma-homeops'
# cloudflare/dns/ (which must never declare sso.realliance.net). The explicit record wins
# over the *.realliance.net wildcard that points at the homelab.
variable "sso_ip" {
  description = "Public IPv4 of the box running Realliance SSO. Change it here during a restore."
  type        = string
  default     = "23.163.0.48"
}

resource "cloudflare_dns_record" "sso" {
  zone_id = local.zone_id
  name    = "sso.realliance.net"
  type    = "A"
  content = var.sso_ip
  proxied = false
  ttl     = 300
  comment = "Realliance SSO (Keycloak). Managed by realliance/sso dns/."
}
