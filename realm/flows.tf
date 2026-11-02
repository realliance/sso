# The realm's browser flow (no access check): password, then required MFA.
module "realm_browser" {
  source   = "./modules/browser_flow"
  realm_id = keycloak_realm.realliance.id
  prefix   = "realliance"
}

resource "keycloak_authentication_bindings" "realliance" {
  realm_id     = keycloak_realm.realliance.id
  browser_flow = module.realm_browser.alias
  depends_on   = [module.realm_browser]
}

# Re-home the original top-level resources into the module without rebuilding them.
moved {
  from = keycloak_authentication_flow.browser
  to   = module.realm_browser.keycloak_authentication_flow.this
}
moved {
  from = keycloak_authentication_execution.browser_cookie
  to   = module.realm_browser.keycloak_authentication_execution.cookie
}
moved {
  from = keycloak_authentication_execution.browser_idp_redirector
  to   = module.realm_browser.keycloak_authentication_execution.idp_redirector
}
moved {
  from = keycloak_authentication_subflow.browser_forms
  to   = module.realm_browser.keycloak_authentication_subflow.forms
}
moved {
  from = keycloak_authentication_execution.forms_username_password
  to   = module.realm_browser.keycloak_authentication_execution.username_password
}
moved {
  from = keycloak_authentication_subflow.mfa
  to   = module.realm_browser.keycloak_authentication_subflow.mfa
}
moved {
  from = keycloak_authentication_subflow.mfa_choose
  to   = module.realm_browser.keycloak_authentication_subflow.mfa_choose
}
moved {
  from = keycloak_authentication_execution.mfa_has_factor
  to   = module.realm_browser.keycloak_authentication_execution.mfa_has_factor
}
moved {
  from = keycloak_authentication_execution.mfa_option
  to   = module.realm_browser.keycloak_authentication_execution.mfa_option
}
moved {
  from = keycloak_authentication_subflow.mfa_enroll
  to   = module.realm_browser.keycloak_authentication_subflow.mfa_enroll
}
moved {
  from = keycloak_authentication_execution.mfa_choose_skipped
  to   = module.realm_browser.keycloak_authentication_execution.mfa_choose_skipped
}
moved {
  from = keycloak_authentication_execution_config.mfa_choose_skipped
  to   = module.realm_browser.keycloak_authentication_execution_config.mfa_choose_skipped
}
moved {
  from = keycloak_authentication_execution.mfa_enroll_totp
  to   = module.realm_browser.keycloak_authentication_execution.mfa_enroll_totp
}
