# Realliance's own Backblaze account (not Chris's personal one): buckets and the narrow keys
# everything else uses. Bucket names are global in B2.

resource "b2_bucket" "tfstate" {
  bucket_name = "realliance-sso-tfstate"
  bucket_type = "allPrivate"

  default_server_side_encryption {
    mode      = "SSE-B2"
    algorithm = "AES256"
  }

  # Old state versions stay recoverable for 90 days.
  lifecycle_rules {
    file_name_prefix             = ""
    days_from_hiding_to_deleting = 90
  }
}

resource "b2_bucket" "backups" {
  bucket_name = "realliance-sso-backups"
  bucket_type = "allPrivate"

  # Object Lock: no dump version can be deleted for 30 days by anything but the master key.
  # Without it, a writeFiles key can *hide* every dump and the lifecycle purges them a day later.
  file_lock_configuration {
    is_file_lock_enabled = true
    default_retention {
      mode = "governance"
      period {
        duration = 30
        unit     = "days"
      }
    }
  }

  default_server_side_encryption {
    mode      = "SSE-B2"
    algorithm = "AES256"
  }

  # 30 nightly dumps: each hides after 30 days and is purged a day later, so the
  # backup key never needs delete rights.
  lifecycle_rules {
    file_name_prefix              = "keycloak/"
    days_from_uploading_to_hiding = 30
    days_from_hiding_to_deleting  = 1
  }
}

# OpenTofu state for b2/, dns/ and realm/ (lock files need deleteFiles).
resource "b2_application_key" "tfstate" {
  key_name     = "realliance-sso-tfstate"
  bucket_ids   = [b2_bucket.tfstate.bucket_id]
  capabilities = ["listBuckets", "listFiles", "readFiles", "writeFiles", "deleteFiles"]
}

# The box's nightly pg_dump upload. No deleteFiles: a compromised box cannot erase backups.
resource "b2_application_key" "backup" {
  key_name     = "realliance-sso-backup"
  bucket_ids   = [b2_bucket.backups.bucket_id]
  capabilities = ["listBuckets", "listFiles", "readFiles", "writeFiles"]
}
