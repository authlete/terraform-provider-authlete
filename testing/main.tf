terraform {
  required_providers {
    authlete = {
      source = "authlete/authlete"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# Key generation stays with hashicorp/tls, which already handles generating once
# and holding it in state. The provider supplies only the PEM -> JWK conversion,
# which is deterministic and therefore safe as a Terraform function.
resource "tls_private_key" "signing" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

variable "name_prefix" {
  description = "Prefix for created object names, so test artifacts are identifiable."
  type        = string
  default     = "tftest"
}

variable "organization_id" {
  description = "Authlete organization the service is created under. Required by the IdP create endpoint."
  type        = number
}

# Deliberately empty. The provider reads AUTHLETE_TOKEN and AUTHLETE_SERVER_URL
# from the environment, so no credential appears in configuration at all.
#
# Creating a service needs an Organization Token — a Service Access Token is
# scoped to one existing service and cannot create new ones.
#
# tls_skip_verify and http_headers are also available here for on-premise
# deployments behind a private CA or a proxy.
provider "authlete" {}

# ---------------------------------------------------------------------------
# A service. Every other Authlete object lives underneath one.
#
# The `service` schema has ~200 optional attributes and no required ones; this
# sets the handful that define a usable authorization server and leaves the rest
# at Authlete's defaults. See docs/resources/service.md for the full surface.
# ---------------------------------------------------------------------------
resource "authlete_service" "test" {
  # Create and delete go through the IdP; read and update go to the regional
  # cluster in AUTHLETE_SERVER_URL. api_server_id is deliberately omitted --
  # the provider derives it from the cluster and injects it. Self-managed
  # deployments that the provider cannot map should set it explicitly here.
  organization_id = var.organization_id

  service_name = "${var.name_prefix}-service"
  issuer       = "https://${var.name_prefix}.example.com"
  description  = "Created by terraform-provider-authlete testing/run.sh"

  supported_scopes = [
    { name = "openid" },
    { name = "profile" },
  ]

  supported_grant_types    = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]

  access_token_duration  = 3600
  refresh_token_duration = 86400

  # JWK experiment. The spec models this as one opaque string, so the generated
  # provider cannot offer the structured `jwk` block the hand-written provider
  # has. The open question is whether the string round-trips: if Authlete stores
  # it back in any different form, every plan reports a change forever.
  jwks = jsonencode({
    keys = [jsondecode(provider::authlete::jwk_from_pem(
      tls_private_key.signing.private_key_pem, "tftest-service-key", "RS256", "sig"))]
  })
}

# ---------------------------------------------------------------------------
# A client under that service.
#
# service_id is a String on this resource while the service exports api_key as a
# Number, so it needs tostring(). That asymmetry is real: the client endpoints
# still type serviceId as a string in the spec, and only clientId was retyped in
# the overlay.
# ---------------------------------------------------------------------------
resource "authlete_client" "test" {
  service_id = tostring(authlete_service.test.api_key)

  client_name    = "${var.name_prefix}-client"
  client_type    = "CONFIDENTIAL"
  redirect_uris  = ["https://${var.name_prefix}.example.com/callback"]
  grant_types    = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  response_types = ["CODE"]

  # A client publishes public keys only, so it gets the public PEM.
  jwks = jsonencode({
    keys = [jsondecode(provider::authlete::jwk_from_pem(
      tls_private_key.signing.public_key_pem, "tftest-client-key", "RS256", "sig"))]
  })
}

# ---------------------------------------------------------------------------
# Read both back through the data sources, which exercises the read path
# independently of the resources' own state.
# ---------------------------------------------------------------------------
// The service data source takes api_key, not service_id: the overlay's
// x-speakeasy-match: apiKey folded the serviceId path param into the api_key
// attribute. The client data source still takes a separate service_id string.
data "authlete_service" "readback" {
  api_key = authlete_service.test.api_key
}

data "authlete_client" "readback" {
  service_id = tostring(authlete_service.test.api_key)
  client_id  = authlete_client.test.client_id
}

output "service_api_key" {
  description = "Service ID assigned by Authlete; the value used in API paths."
  value       = authlete_service.test.api_key
}

output "service_name_readback" {
  description = "Service name as returned by the data source, not from resource state."
  value       = data.authlete_service.readback.service_name
}

output "client_id" {
  value = authlete_client.test.client_id
}

output "client_name_readback" {
  value = data.authlete_client.readback.client_name
}

output "client_secret" {
  description = "Marked sensitive; read with: terraform output -raw client_secret"
  value       = authlete_client.test.client_secret
  sensitive   = true
}
