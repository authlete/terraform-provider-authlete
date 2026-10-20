# A shared secret too short for its algorithm.
#
# RFC 7518 requires an HMAC key at least as long as the hash output. Authlete
# stores a shorter one happily and fails only when it comes to sign with it.
#
# This one exercises jwk_from_secret rather than the jwks attribute, so it is a
# plan: the function runs while the expression is evaluated.
terraform {
  required_providers {
    authlete = { source = "authlete/authlete" }
  }
}

provider "authlete" {
  organization_id = 1
}

resource "authlete_service" "short_secret" {
  service_name = "negative-short-secret"
  issuer       = "https://negative-short-secret.example"

  jwks = jsonencode({
    keys = [jsondecode(provider::authlete::jwk_from_secret(
      "too-short", "hmac-1", "HS256", "sig"))]
  })
}
