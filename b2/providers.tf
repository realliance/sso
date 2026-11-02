terraform {
  required_version = ">= 1.10"
  required_providers {
    b2 = {
      source  = "Backblaze/b2"
      version = "~> 0.14.1"
    }
  }
}

# Reads B2_APPLICATION_KEY_ID / B2_APPLICATION_KEY (the Realliance account's master key,
# from realliance/sso-secrets/b2/secrets.env). Operator laptops only — never CI, never the box.
provider "b2" {}
