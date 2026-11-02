variable "realm_id" { type = string }

variable "prefix" {
  description = "Flow alias is <prefix>-browser; subflow aliases are <prefix>-mfa, <prefix>-browser-forms, ..."
  type        = string
}

variable "description" {
  type    = string
  default = "Password, then MFA (TOTP, FIDO2/passkey, recovery code)."
}

variable "deny_unless_role" {
  description = "Client role (\"<clientId>.<role>\") a user must hold, or null for no access check."
  type        = string
  default     = null
}
