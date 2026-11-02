terraform {
  required_version = ">= 1.11"
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "~> 5.10.0"
    }
  }
}

# Service-account auth against master. Secret from KEYCLOAK_CLIENT_SECRET; CI's plan job sets
# TF_VAR_keycloak_client_id=tofu-plan (view-only), apply uses tofu-apply.
provider "keycloak" {
  url       = var.keycloak_url
  realm     = "master"
  client_id = var.keycloak_client_id
}
