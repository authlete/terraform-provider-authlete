# Two keys sharing a kid.
#
# Authlete selects a key by its kid, so which of the two is used would be
# undefined. The set is stored anyway, since it is an opaque string to the API.
terraform {
  required_providers {
    authlete = { source = "authlete/authlete" }
  }
}

provider "authlete" {
  organization_id = 1
}

resource "authlete_service" "dup_kid" {
  service_name = "negative-duplicate-kid"
  issuer       = "https://negative-duplicate-kid.example"

  jwks = jsonencode({
    keys = [
      { kty = "RSA", kid = "dup", alg = "RS256", use = "sig", n = "AQAB", e = "AQAB" },
      { kty = "RSA", kid = "dup", alg = "PS256", use = "sig", n = "AQAB", e = "AQAB" },
    ]
  })
}
