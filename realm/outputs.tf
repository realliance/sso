output "realm_id" { value = keycloak_realm.realliance.id }
output "browser_flow_alias" { value = module.realm_browser.alias }
