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

  dynamic "attribute" {
    for_each = { firstName = "$${firstName}", lastName = "$${lastName}" }
    content {
      name               = attribute.key
      display_name       = attribute.value
      required_for_roles = ["user"]
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
