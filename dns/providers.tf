terraform {
  required_version = ">= 1.10"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

# Reads CLOUDFLARE_API_TOKEN (Zone > DNS > Edit, realliance.net only) from
# realliance/sso-secrets/dns/secrets.env.
provider "cloudflare" {}
