output "realm_id" { value = keycloak_realm.realliance.id }
output "browser_flow_alias" { value = module.realm_browser.alias }

# Client secrets for CONFIDENTIAL apps, for the app owner (README "Adding an app").
output "app_client_secrets" {
  # Add `<name> = module.<name>.client_secret` for each CONFIDENTIAL app (README "Adding an app").
  value = {
    forgejo = module.forgejo.client_secret
  }
  sensitive = true
}
