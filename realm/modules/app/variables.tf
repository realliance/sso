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

variable "home_url" {
  description = "The app's address, linked from the account console's Applications page."
  type        = string
  default     = null
}

variable "always_display_in_console" {
  description = "List the app in the account console even before someone has used it."
  type        = bool
  default     = false
}
