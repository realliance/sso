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

variable "keycloak_url" {
  description = "Keycloak base URL. The box applies against http://127.0.0.1:8080."
  type        = string
  default     = "https://sso.realliance.net"
}
