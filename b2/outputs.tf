output "tfstate_key_id" { value = b2_application_key.tfstate.application_key_id }
output "tfstate_key" {
  value     = b2_application_key.tfstate.application_key
  sensitive = true
}
output "backup_key_id" { value = b2_application_key.backup.application_key_id }
output "backup_key" {
  value     = b2_application_key.backup.application_key
  sensitive = true
}
