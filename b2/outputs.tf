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

output "forge_objects_key_id" { value = b2_application_key.forge_objects.application_key_id }
output "forge_objects_key" {
  value     = b2_application_key.forge_objects.application_key
  sensitive = true
}
output "forge_objects_ro_key_id" { value = b2_application_key.forge_objects_ro.application_key_id }
output "forge_objects_ro_key" {
  value     = b2_application_key.forge_objects_ro.application_key
  sensitive = true
}
output "forge_backup_key_id" { value = b2_application_key.forge_backup.application_key_id }
output "forge_backup_key" {
  value     = b2_application_key.forge_backup.application_key
  sensitive = true
}
