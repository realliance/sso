# State in the Realliance B2 account. No lockfile: B2 rejects the conditional PutObject it
# needs; CI applies run in a concurrency group and old state versions are kept 90 days.
terraform {
  backend "s3" {
    bucket                      = "realliance-sso-tfstate"
    key                         = "realm/terraform.tfstate"
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
