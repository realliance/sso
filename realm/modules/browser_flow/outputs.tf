output "alias" { value = keycloak_authentication_flow.this.alias }
output "id" { value = keycloak_authentication_flow.this.id }

# Depend on this before binding the flow, so it is never bound half-built.
output "ready" {
  value = concat(
    [keycloak_authentication_execution.cookie.id, keycloak_authentication_execution.idp_redirector.id,
      keycloak_authentication_execution.username_password.id, keycloak_authentication_execution.mfa_has_factor.id,
    keycloak_authentication_execution_config.mfa_choose_skipped.id, keycloak_authentication_execution.mfa_enroll_totp.id],
    [for e in keycloak_authentication_execution.mfa_option : e.id],
    keycloak_authentication_execution_config.lacks_role[*].id,
    keycloak_authentication_execution.deny[*].id,
  )
}
