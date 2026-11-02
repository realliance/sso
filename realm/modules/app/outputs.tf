output "client_uuid" { value = keycloak_openid_client.this.id }
output "access_group_id" { value = keycloak_group.access.id }
output "browser_flow_alias" { value = module.browser.alias }
