variable "keycloak_client_id" {
  description = "master-realm service account OpenTofu authenticates as (tofu-apply or tofu-plan)."
  type        = string
  default     = "tofu-apply"
}

variable "smtp_password" {
  description = "Resend sending-only key restricted to realliance.net."
  type        = string
  sensitive   = true
}
