# A misspelled key type.
#
# Authlete accepts the request with a 200 and drops the key, storing
# {"keys":[]}, so the apply succeeds and every later plan offers it again.
terraform {
  required_providers {
    authlete = { source = "authlete/authlete" }
  }
}

provider "authlete" {
  organization_id = 1
}

resource "authlete_service" "bad_kty" {
  service_name = "negative-kty"
  issuer       = "https://negative-kty.example"

  # "RSA", lowercased.
  jwks = jsonencode({
    keys = [{ kty = "rsa", kid = "k1", use = "sig" }]
  })
}
