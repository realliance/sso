# State lives in the bucket this layer creates. Bootstrap once (docs/runbook.md, "B2 bootstrap"):
# apply with this file moved aside (local state), then restore it and `tofu init -migrate-state`.
# The S3 API cannot use B2 master keys, so the backend authenticates with the tfstate key below
# (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from b2/secrets.env). No state locking on B2: serialise
# applies (CI uses a concurrency group); old state versions stay recoverable for 90 days.
terraform {
  backend "s3" {
    bucket                      = "realliance-sso-tfstate"
    key                         = "b2/terraform.tfstate"
    region                      = "us-east-005"
    endpoints                   = { s3 = "https://s3.us-east-005.backblazeb2.com" }
    use_lockfile                = false # B2 rejects the conditional PutObject (501) that S3 lockfiles need
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}
