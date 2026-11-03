# "Link GitHub" on the account page (Linked accounts): proves a person's GitHub username for
# Realliance tools (the forge's GitHub mirroring, forge-bot). LINK-ONLY: GitHub is never offered
# on the sign-in page and can never sign anyone in or create an account. Consumers read the link
# through the admin API (users/{id}/federated-identity), not from tokens.
#
# The GitHub OAuth app lives in the realliance GitHub org; its callback is
# https://sso.realliance.net/realms/realliance/broker/github/endpoint. Created only once its secret
# is configured, so this file can merge before the app exists.

variable "github_client_id" {
  description = "Client ID of the realliance GitHub org's \"Realliance SSO\" OAuth app."
  type        = string
  default     = null
}

variable "github_client_secret" {
  type      = string
  default   = null
  sensitive = true
}

resource "keycloak_oidc_github_identity_provider" "github" {
  count              = var.github_client_secret == null ? 0 : 1
  realm              = keycloak_realm.realliance.id
  client_id          = var.github_client_id
  client_secret      = var.github_client_secret
  link_only          = true
  hide_on_login_page = true
  trust_email        = false
  store_token        = false
  sync_mode          = "IMPORT"
  default_scopes     = "read:user" # the username is all we need
}
