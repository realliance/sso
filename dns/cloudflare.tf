# Cloudflare edge for sso.realliance.net (proxied). Bot protection is a Managed Challenge on the
# forgot-password pages only; every other path on this host skips Cloudflare's browser/security
# checks so CLIs, apps, CI and the box itself are never challenged.
#
# NB these are the zone's ENTRY-POINT rulesets for their phases (one per zone): any other
# realliance.net config/WAF rules must be added here, not in a second ruleset.

resource "cloudflare_ruleset" "config" {
  zone_id     = local.zone_id
  name        = "realliance.net configuration rules"
  description = "Managed by realliance/sso dns/."
  kind        = "zone"
  phase       = "http_config_settings"
  rules = [{
    ref         = "sso_ssl_strict"
    description = "sso: Full (strict) TLS to the origin (the zone default is off)"
    expression  = "(http.host eq \"sso.realliance.net\")"
    action      = "set_config"
    action_parameters = {
      ssl = "strict"
    }
    enabled = true
  }]
}

locals {
  sso_reset = "(http.host eq \"sso.realliance.net\" and http.request.uri.path contains \"/login-actions/reset-credentials\")"
}

resource "cloudflare_ruleset" "waf" {
  zone_id     = local.zone_id
  name        = "realliance.net custom WAF rules"
  description = "Managed by realliance/sso dns/."
  kind        = "zone"
  phase       = "http_request_firewall_custom"
  rules = [
    {
      ref         = "sso_skip_checks"
      description = "sso: never challenge anything except the reset pages (CLIs, apps, CI, the box)"
      expression  = "(http.host eq \"sso.realliance.net\" and not ${local.sso_reset})"
      action      = "skip"
      action_parameters = {
        products = ["bic", "securityLevel", "uaBlock"]
      }
      logging = { enabled = true }
      enabled = true
    },
    {
      ref         = "sso_reset_challenge"
      description = "sso: Managed Challenge (Turnstile) on the forgot-password page"
      expression  = "(${local.sso_reset} and http.request.method eq \"GET\")"
      action      = "managed_challenge"
      enabled     = true
    },
    {
      ref         = "sso_reset_post_needs_clearance"
      description = "sso: forgot-password submissions must come from a browser that passed the challenge"
      expression  = "(${local.sso_reset} and http.request.method ne \"GET\" and not http.cookie contains \"cf_clearance\")"
      action      = "block"
      enabled     = true
    },
  ]
}
