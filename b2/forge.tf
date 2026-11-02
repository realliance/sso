# Realliance forge (git.realliance.net, project 2): binaries and off-site backups.
# Spec: luma-homeops docs/superpowers/specs/2026-11-02-realliance-forge-design.md

# LFS, packages, attachments, avatars and archives (Forgejo [storage] minio). Every upload is a
# version; Forgejo deletes by hiding, and hidden versions are purged after 30 days.
resource "b2_bucket" "forge_objects" {
  bucket_name = "realliance-forge-objects"
  bucket_type = "allPrivate"

  default_server_side_encryption {
    mode      = "SSE-B2"
    algorithm = "AES256"
  }

  lifecycle_rules {
    file_name_prefix             = ""
    days_from_hiding_to_deleting = 30
  }
}

# Nightly Postgres dumps (spilo/, postgres-operator logical backup) and `forgejo dump` archives
# (dump/). Object Lock: no version can be deleted for 30 days by anything but the master key.
resource "b2_bucket" "forge_backups" {
  bucket_name = "realliance-forge-backups"
  bucket_type = "allPrivate"

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

  lifecycle_rules {
    file_name_prefix              = "spilo/"
    days_from_uploading_to_hiding = 30
    days_from_hiding_to_deleting  = 1
  }

  lifecycle_rules {
    file_name_prefix              = "dump/"
    days_from_uploading_to_hiding = 30
    days_from_hiding_to_deleting  = 1
  }
}

# Forgejo itself. No deleteFiles: it can hide objects, never destroy a version.
resource "b2_application_key" "forge_objects" {
  key_name     = "realliance-forge-objects"
  bucket_ids   = [b2_bucket.forge_objects.bucket_id]
  capabilities = ["listBuckets", "listFiles", "readFiles", "writeFiles"]
}

# Restore drills: a second Forgejo can read the live bucket without touching it.
resource "b2_application_key" "forge_objects_ro" {
  key_name     = "realliance-forge-objects-ro"
  bucket_ids   = [b2_bucket.forge_objects.bucket_id]
  capabilities = ["listBuckets", "listFiles", "readFiles"]
}

# The forgejo namespace's backup writers (logical backup + dump CronJob). No deleteFiles.
resource "b2_application_key" "forge_backup" {
  key_name     = "realliance-forge-backup"
  bucket_ids   = [b2_bucket.forge_backups.bucket_id]
  capabilities = ["listBuckets", "listFiles", "readFiles", "writeFiles"]
}
