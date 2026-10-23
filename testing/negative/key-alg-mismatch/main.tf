# An RSA key published for HS256.
#
# Authlete stores a JWK Set without inspecting it, so this used to be saved and
# served. It is the shape of an algorithm confusion attack: a verifier that
# trusts the published alg could be led to use the public key as an HMAC secret.
terraform {
  required_providers {
    authlete = { source = "authlete/authlete" }
  }
}

provider "authlete" {
  organization_id = 1
}

resource "authlete_service" "alg_mismatch" {
  service_name = "negative-alg-mismatch"
  issuer       = "https://negative-alg-mismatch.example"

  jwks = jsonencode({
    keys = [{ kty = "RSA", kid = "k1", alg = "HS256", use = "sig", n = "AQAB", e = "AQAB" }]
  })
}
