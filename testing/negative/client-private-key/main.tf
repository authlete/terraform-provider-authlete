# A private key in a client's JWK Set.
#
# A client's keys are the ones Authlete verifies that client with, so they must
# be public. Authlete strips the private members without reporting an error,
# which leaves the configuration and the server disagreeing for ever, and the
# private key sitting in Terraform state for a key the server never kept.
terraform {
  required_providers {
    authlete = { source = "authlete/authlete" }
  }
}

provider "authlete" {
  organization_id = 1
}

resource "authlete_client" "private_key" {
  service_id  = 1
  client_name = "negative-client-private-key"

  jwks = jsonencode({
    keys = [{
      kty = "RSA", kid = "k1", alg = "RS256", use = "sig",
      n = "AQAB", e = "AQAB",
      d = "c2VjcmV0",
    }]
  })
}
