variable "realm_id" { type = string }
variable "client_id" { type = string }
variable "name" { type = string }
variable "redirect_uris" { type = list(string) }
variable "apps_parent_group_id" { type = string }

variable "roles" {
  type    = list(string)
  default = ["user"]
}

variable "extra_default_scopes" {
  description = "Client scopes beyond the realm defaults, e.g. [\"groups\"]."
  type        = list(string)
  default     = []
}

variable "access_type" {
  type    = string
  default = "CONFIDENTIAL"
}

variable "direct_access_grants" {
  description = "Password grant (test clients only — it bypasses the browser flow's MFA)."
  type        = bool
  default     = false
}

variable "enabled" {
  type    = bool
  default = true
}
