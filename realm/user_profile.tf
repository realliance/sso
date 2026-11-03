# Declarative user profile. Keycloak drops attributes the profile does not declare, so `mfa`
# (first-time second factor, set from realliance/sso-people) must be declared here. The four
# default attributes are reproduced as Keycloak ships them.
resource "keycloak_realm_user_profile" "realliance" {
  realm_id = keycloak_realm.realliance.id

  attribute {
    name         = "username"
    display_name = "$${username}"
    permissions {
      view = ["admin", "user"]
      edit = ["admin", "user"]
    }
    validator {
      name   = "length"
      config = { min = "3", max = "255" }
    }
    validator { name = "username-prohibited-characters" }
    validator { name = "up-username-not-idn-homograph" }
  }

  attribute {
    name               = "email"
    display_name       = "$${email}"
    required_for_roles = ["user"]
    permissions {
      view = ["admin", "user"]
      edit = ["admin", "user"]
    }
    validator { name = "email" }
    validator {
      name   = "length"
      config = { max = "255" }
    }
  }

  # First name is what apps greet people by; a last name is optional — many people would rather
  # not give their full name. (null omits required_for_roles; an empty list would mean "always".)
  dynamic "attribute" {
    for_each = {
      firstName = { label = "$${firstName}", required = true }
      lastName  = { label = "Last name (optional)", required = false }
    }
    content {
      name               = attribute.key
      display_name       = attribute.value.label
      required_for_roles = attribute.value.required ? ["user"] : null
      permissions {
        view = ["admin", "user"]
        edit = ["admin", "user"]
      }
      validator {
        name   = "length"
        config = { max = "255" }
      }
      validator { name = "person-name-prohibited-characters" }
    }
  }

  # Optional and self-editable on the account page. forge-bot copies it into Forgejo's pronouns
  # field.
  attribute {
    name         = "pronouns"
    display_name = "Pronouns (optional)"
    permissions {
      view = ["admin", "user"]
      edit = ["admin", "user"]
    }
    validator {
      name   = "length"
      config = { max = "40" }
    }
  }

  # Avatar URL. Written only by forge-bot (the Forgejo avatar URL); people can see it but not edit it.
  attribute {
    name         = "picture"
    display_name = "Avatar URL"
    permissions {
      view = ["admin", "user"]
      edit = ["admin"]
    }
    validator {
      name   = "length"
      config = { max = "255" }
    }
  }

  # First-time MFA enrolment: webauthn (FIDO2 key / passkey) or totp. Admin-managed only.
  attribute {
    name          = "mfa"
    display_name  = "First-time MFA"
    default_value = "webauthn"
    group         = "user-metadata"
    permissions {
      view = ["admin"]
      edit = ["admin"]
    }
    validator {
      name   = "options"
      config = { options = jsonencode(["webauthn", "totp"]) }
    }
  }

  group {
    name                = "user-metadata"
    display_header      = "User metadata"
    display_description = "Attributes, which refer to user metadata"
  }
}
