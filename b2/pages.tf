# Realliance Pages (realliance.page): git-pages site state.
# Spec: luma-homeops docs/superpowers/specs (Realliance Pages design); plan decision D5.
#
# D5: git-pages calls S3 RemoveObject without a version. On B2 that only hides the file, so the
# key needs no deleteFiles. Hidden versions are purged after 1 day; the state is rebuildable.
resource "b2_bucket" "forge_pages" {
  bucket_name = "realliance-pages"
  bucket_type = "allPrivate"

  default_server_side_encryption {
    mode      = "SSE-B2"
    algorithm = "AES256"
  }

  lifecycle_rules {
    file_name_prefix             = ""
    days_from_hiding_to_deleting = 1
  }
}

# git-pages itself. No deleteFiles: it can hide objects, never destroy a version.
resource "b2_application_key" "forge_pages" {
  key_name     = "realliance-pages"
  bucket_ids   = [b2_bucket.forge_pages.bucket_id]
  capabilities = ["listBuckets", "listFiles", "readFiles", "writeFiles"]
}
