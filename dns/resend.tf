# Resend (Keycloak's outgoing mail) sender records for realliance.net. Values come from Resend's
# domain setup (region us-east-1); the DKIM value is a public key. These are the only other
# records this layer owns — Fastmail's MX/SPF for realliance.net are not managed here.
locals {
  zone_id = "797612475ed6a8f7193a623ffc107f07" # realliance.net
}

resource "cloudflare_dns_record" "resend_dkim" {
  zone_id = local.zone_id
  name    = "resend._domainkey.realliance.net"
  type    = "TXT"
  content = "\"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR16JDhCGSrJMgC/dttVjycs4ma6l7JAG92AU11HD+9Xpxw7EzlLqLs0B3GKCLbVVxaHlwzs7kzbdkybFBiA9ulv8XRl5xQMARDo0WqlRnTDgyerJm4puQPJhnlejeWqd7CAnar4aX6MJJKJMkdL2EWN/id2mk7JiReb4aJmv9QwIDAQAB\""
  ttl     = 1
  comment = "Resend DKIM (Realliance SSO mail). Managed by realliance/sso dns/."
}

resource "cloudflare_dns_record" "resend_bounce_mx" {
  zone_id  = local.zone_id
  name     = "send.realliance.net"
  type     = "MX"
  content  = "feedback-smtp.us-east-1.amazonses.com"
  priority = 10
  ttl      = 1
  comment  = "Resend bounce/return-path MX. Managed by realliance/sso dns/."
}

resource "cloudflare_dns_record" "resend_bounce_spf" {
  zone_id = local.zone_id
  name    = "send.realliance.net"
  type    = "TXT"
  content = "\"v=spf1 include:amazonses.com ~all\""
  ttl     = 1
  comment = "Resend return-path SPF. Managed by realliance/sso dns/."
}

resource "cloudflare_dns_record" "resend_rsend" {
  zone_id = local.zone_id
  name    = "rsend.realliance.net"
  type    = "CNAME"
  content = "send.forge.rmta.net"
  proxied = false
  ttl     = 1
  comment = "Resend return-path CNAME. Managed by realliance/sso dns/."
}
