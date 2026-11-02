# State in the Realliance B2 account (see b2/). No lockfile: B2 rejects the conditional
# PutObject it needs — this layer only changes during a restore, by one operator at a time.
terraform {
  backend "s3" {
    bucket                      = "realliance-sso-tfstate"
    key                         = "dns/terraform.tfstate"
    region                      = "us-east-005"
    endpoints                   = { s3 = "https://s3.us-east-005.backblazeb2.com" }
    use_lockfile                = false
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}
