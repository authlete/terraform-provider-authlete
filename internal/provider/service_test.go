package provider

import (
	"fmt"
	"strconv"
	"testing"

	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var srvToImport authlete.Service

func TestAccResourceService_basic(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceServiceDefaultValues,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.prod", "issuer", "https://test.com"),
					resource.TestCheckFunc(CheckOutputPresent("api_key")),
					resource.TestCheckFunc(CheckOutputPresent("api_secret")),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_grant_types.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_grant_types.0", "AUTHORIZATION_CODE"),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_grant_types.1", "REFRESH_TOKEN"),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_response_types.#", "1"),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_response_types.0", "CODE"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_authorization_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_token_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_revocation_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_user_info_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_introspection_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "single_access_token_per_subject", "false"),
				),
			},
			{
				ResourceName:            "authlete_service.prod",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"api_secret"},
			},
		},
	})
}

func TestAccResourceService_extended(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config:             testAccResourceServiceEveryAttribute,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.complete_described", "service_name", "attributes coverage test"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "issuer", "https://test.com"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "description", "Attributes support test"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "clients_per_developer", "1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "client_id_alias_enabled", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "attribute.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "attribute.1.key", "high_risk_scopes"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "attribute.1.value", "scope1 scope2 scope3"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "attribute.0.key", "require_2_fa"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "attribute.0.value", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_custom_client_metadata.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_custom_client_metadata.0", "basic_review"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_custom_client_metadata.1", "domain_match"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authentication_callback_endpoint", "https://api.mystore.com/authenticate"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authentication_callback_api_key", "lkjl3k44235kjlk5j43kjdkfslkdf"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authentication_callback_api_secret", "lknasdljjk42j435kjh34jkkjr"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_acrs.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_acrs.0", "loa2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_acrs.1", "loa3"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "developer_authentication_callback_endpoint", "https://api.mystore.com/partner_auth"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "developer_authentication_callback_api_key", "lkjl3k44235kjlk5j43kjdkfslkdf"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "developer_authentication_callback_api_secret", "lknasdljjk42j435kjh34jkkjr"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_grant_types.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_grant_types.0", "AUTHORIZATION_CODE"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_grant_types.1", "REFRESH_TOKEN"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_response_types.0", "CODE"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_authorization_detail_types.0", "payment_initiation"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_service_profiles.0", "FAPI"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_service_profiles.1", "OPEN_BANKING"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "error_description_omitted", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "error_uri_omitted", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authorization_endpoint", "https://www.mystore.com/authorize"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "direct_authorization_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_ui_locales.#", "4"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_displays.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "pkce_required", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "pkce_s256_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authorization_response_duration", "10"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "iss_response_suppressed", "true"),
					// resource.TestCheckResourceAttr("authlete_service.complete_described", "ignore_port_loopback_redirect", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "token_endpoint", "https://api.mystore.com/token"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "direct_token_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_token_auth_methods.0", "CLIENT_SECRET_POST"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_token_auth_methods.1", "TLS_CLIENT_AUTH"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "mutual_tls_validate_pki_cert_chain", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "trusted_root_certificates.#", "1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "missing_client_id_allowed", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "revocation_endpoint", "https://api.mystore.com/revoke"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "direct_revocation_endpoint_enabled", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_revocation_auth_methods.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_revocation_auth_methods.0", "CLIENT_SECRET_POST"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_revocation_auth_methods.1", "TLS_CLIENT_AUTH"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "pushed_auth_req_endpoint", "https://api.mystore.com/pushed"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "pushed_auth_req_duration", "10"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "par_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "request_object_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "traditional_request_object_processing_applied", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "nbf_optional", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "front_channel_encryption_request_obj_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "encryption_alg_req_obj_match", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "encryption_enc_alg_req_obj_match", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "access_token_type", "Bearer"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "tls_client_certificate_bound_access_tokens", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "access_token_duration", "99"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "single_access_token_per_subject", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "access_token_sign_alg", "PS256"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "access_token_signature_key_id", "kid1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "refresh_token_duration", "150"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "refresh_token_duration_kept", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "refresh_token_duration_reset", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "refresh_token_kept", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "token_expiration_link", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.0.name", "address"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.0.default_entry", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.0.description", "A permission to request an OpenID Provider to include the address claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details."),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.1.name", "email"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.1.default_entry", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.1.description", "A permission to request an OpenID Provider to include the email claim and the email_verified claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details."),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.1.attribute.#", "1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.1.attribute.0.key", "key1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.1.attribute.0.value", "val1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "scope_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "id_token_duration", "98"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "allowable_clock_skew", "1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_claim_types.#", "3"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_claim_locales.#", "3"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_claims.#", "4"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "claim_shortcut_restrictive", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "jwks_endpoint", "https://www.mystore.com/jwks"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "direct_jwks_endpoint_enabled", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "id_token_signature_key_id", "kid1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "user_info_signature_key_id", "kid1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authorization_signature_key_id", "kid2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "hsm_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "user_info_endpoint", "https://api.mystore.com/userinfo"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "direct_user_info_endpoint_enabled", "false"),
					// resource.TestCheckResourceAttr("authlete_service.complete_described", "dcr_scope_used_as_requestable", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "registration_endpoint", "https://api.mystore.com/dcr"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "registration_management_endpoint", "https://api.mystore.com/client/"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "mtls_endpoint_aliases.0.name", "test"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "mtls_endpoint_aliases.0.uri", "https://test.com"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "policy_uri", "https://www.mystore.com/policy"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "tos_uri", "https://www.mystore.com/tos"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "service_documentation", "https://www.mystore.com/doc"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_authentication_endpoint", "https://api.mystore.com/ciba"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_backchannel_token_delivery_modes.0", "POLL"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_auth_req_id_duration", "15"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backcannel_polling_interval", "3"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_user_code_parameter_supported", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_binding_message_required_in_fapi", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_authorization_endpoint", "https://api.mystore.com/device"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_verification_uri", "https://api.mystore.com/devverify"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_verification_uri_complete", "https://example.com/verification?user_code=USER_CODE"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_flow_code_duration", "10"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_flow_polling_interval", "1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "user_code_charset", "NUMERIC"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "user_code_length", "6"),
					/*
						resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_trust_frameworks.0", "eidas_ial_high"),
						resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_evidence.0", "id_document"),
						resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_evidence.1", "utility_bill"),
						resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_identity_documents.0", "idcard"),
						resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_identity_documents.1", "password"),
						resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_verification_methods.0", "pipp"),
						resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_verified_claims.0", "given_name"),

					*/
					resource.TestCheckResourceAttr("authlete_service.complete_described", "end_session_endpoint", "https://www.mystore.com/endsession"),
				),
			},
			{
				ResourceName:            "authlete_service.complete_described",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"api_secret", "jwk"},
			},
		},
	})
}

const testAccResourceServiceDefaultValues = `
provider "authlete" {
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Simplest Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
}

output "api_key" {  
  value = authlete_service.prod.id
}
output "api_secret" {  
  value = authlete_service.prod.api_secret
}
`

const testAccResourceServiceEveryAttribute = `

provider "authlete" {
	
}

resource "authlete_service" "complete_described" {
  service_name = "attributes coverage test"
  issuer = "https://test.com"
  description = "Attributes support test"
  clients_per_developer = 1
  client_id_alias_enabled = true
  attribute {
  	 key = "require_2_fa"
     value = "true"
  }
  attribute {
  	 key = "high_risk_scopes"
     value = "scope1 scope2 scope3"
  }
  supported_custom_client_metadata = ["basic_review", "domain_match"]
  authentication_callback_endpoint = "https://api.mystore.com/authenticate"
  authentication_callback_api_key = "lkjl3k44235kjlk5j43kjdkfslkdf"
  authentication_callback_api_secret = "lknasdljjk42j435kjh34jkkjr"
  supported_acrs = ["loa2", "loa3"]
  developer_authentication_callback_endpoint = "https://api.mystore.com/partner_auth"
  developer_authentication_callback_api_key = "lkjl3k44235kjlk5j43kjdkfslkdf"
  developer_authentication_callback_api_secret = "lknasdljjk42j435kjh34jkkjr"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  supported_authorization_detail_types = ["payment_initiation",]
  supported_service_profiles = ["FAPI", "OPEN_BANKING",]
  error_description_omitted = true
  error_uri_omitted = false
  authorization_endpoint = "https://www.mystore.com/authorize"
  direct_authorization_endpoint_enabled = false
  supported_ui_locales = ["fr-CA","fr", "en-GB", "en"]
  supported_displays = [ "PAGE", "POPUP" ]
  pkce_required = false
  pkce_s256_required = true
  authorization_response_duration = 10
  iss_response_suppressed = true
  #ignore_port_loopback_redirect = true
  token_endpoint = "https://api.mystore.com/token"
  direct_token_endpoint_enabled = false
  supported_token_auth_methods = ["CLIENT_SECRET_POST", "TLS_CLIENT_AUTH"]
  mutual_tls_validate_pki_cert_chain = true
  trusted_root_certificates = ["-----BEGIN CERTIFICATE-----\r\nMIIDpjCCAo6gAwIBAgIUS3mWeRx1uG/SMl/ql55VwRtNz7wwDQYJKoZIhvcNAQEL\r\nBQAwazELMAkGA1UEBhMCQlIxHDAaBgNVBAoTE09wZW4gQmFua2luZyBCcmFzaWwx\r\nFTATBgNVBAsTDE9wZW4gQmFua2luZzEnMCUGA1UEAxMeT3BlbiBCYW5raW5nIFJv\r\nb3QgU0FOREJPWCAtIEcxMB4XDTIwMTIxMTEwMDAwMFoXDTI1MTIxMDEwMDAwMFow\r\nazELMAkGA1UEBhMCQlIxHDAaBgNVBAoTE09wZW4gQmFua2luZyBCcmFzaWwxFTAT\r\nBgNVBAsTDE9wZW4gQmFua2luZzEnMCUGA1UEAxMeT3BlbiBCYW5raW5nIFJvb3Qg\r\nU0FOREJPWCAtIEcxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp50j\r\njNh0wu8ioziC1HuWqOfgXwxeiePiRGw5tKDqKIbC7XV1ghEcDiymTHHWWJSQ1LEs\r\nmYpZVwaos5Mrz2xJwytg8K5eqFqa7QvfOOul29bnzEFk+1gX/0nOYws3Lba9E7S+\r\nuPaUmfElF4r2lcCNL2f3F87RozqZf+DQBdGUzAt9n+ipY1JpqfI3KF/5qgRkPoIf\r\nJD+aj2Y1D6eYjs5uMRLU8FMYt0CCfv/Ak6mq4Y9/7CaMKp5qjlrrDux00IDpxoXG\r\nKx5cK0KgACb2UBZ98oDQxcGrbRIyp8VGmv68BkEQcm7NljP863uBVxtnVTpRwQ1x\r\nwYEbmSSyoonXy575wQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/\r\nBAUwAwEB/zAdBgNVHQ4EFgQUhxPslj5i7CEcDEpWOvIlDOOU6cswDQYJKoZIhvcN\r\nAQELBQADggEBAFoYqwoH7zvr4v0SQ/hWx/bWFRIcV/Rf6rEWGyT/moVAEjPbGH6t\r\nyHhbxh3RdGcPY7Pzn797lXDGRu0pHv+GAHUA1v1PewCp0IHYukmN5D8+Qumem6by\r\nHyONyUASMlY0lUOzx9mHVBMuj6u6kvn9xjL6xsPS+Cglv/3SUXUR0mMCYf963xnF\r\nBIRLTRlbykgJomUptVl/F5U/+8cD+lB/fcZPoQVI0kK0VV51jAODSIhS6vqzQzH4\r\ncpUmcPh4dy+7RzdTTktxOTXTqAy9/Yx+fk18O9qSQw1MKa9dDZ4YLnAQS2fJJqIE\r\n1DXIta0LpqM4pMoRMXvp9SLU0atVZLEu6Sc=\r\n-----END CERTIFICATE-----"]
  missing_client_id_allowed = true
  revocation_endpoint = "https://api.mystore.com/revoke"
  direct_revocation_endpoint_enabled = true
  supported_revocation_auth_methods = ["CLIENT_SECRET_POST", "TLS_CLIENT_AUTH"]
  pushed_auth_req_endpoint = "https://api.mystore.com/pushed"
  pushed_auth_req_duration = 10
  par_required = true
  request_object_required = true
  traditional_request_object_processing_applied = true
  nbf_optional = false
  front_channel_encryption_request_obj_required = true
  encryption_alg_req_obj_match = true
  encryption_enc_alg_req_obj_match = true
  access_token_type = "Bearer"
  tls_client_certificate_bound_access_tokens = true
  access_token_duration = 99
  single_access_token_per_subject = false
  access_token_sign_alg = "PS256"
  access_token_signature_key_id = "kid1"
  refresh_token_duration = 150
  refresh_token_duration_kept = false
  refresh_token_duration_reset = false
  refresh_token_kept = true
  token_expiration_link = true
  supported_scopes {
	name = "address"
    default_entry = false
    description = "A permission to request an OpenID Provider to include the address claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details."
  }
  supported_scopes {
	name = "email"
    default_entry = true
    description = "A permission to request an OpenID Provider to include the email claim and the email_verified claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details."
    attribute {
		key = "key1"
        value = "val1"
	}
  }
  scope_required = true
  id_token_duration = 98
  allowable_clock_skew = 1
  supported_claim_types = ["NORMAL", "AGGREGATED", "DISTRIBUTED"]
  supported_claim_locales = ["en", "fr", "jp"]
  supported_claims = ["name","email", "profile", "gender"]
  claim_shortcut_restrictive = true
  jwks_endpoint = "https://www.mystore.com/jwks"
  direct_jwks_endpoint_enabled = true
  jwk {
	  kid = "kid1"
	  alg = "RS256" 
	  use = "sig" 
	  kty = "RSA"
   key_size = 2048
      generate = true
   }
  jwk {
	  kid = "kid2"
	  alg = "RS256" 
	  use = "sig" 
   key_size = 2048
	  kty = "RSA"
      generate = true
   }
  id_token_signature_key_id = "kid1"
  user_info_signature_key_id = "kid1"
  authorization_signature_key_id = "kid2"
  hsm_enabled = false
  user_info_endpoint = "https://api.mystore.com/userinfo"
  direct_user_info_endpoint_enabled = false
  #dcr_scope_used_as_requestable = true
  registration_endpoint = "https://api.mystore.com/dcr"
  registration_management_endpoint = "https://api.mystore.com/client/"
  mtls_endpoint_aliases {
	name = "test"
    uri = "https://test.com"
  }
  policy_uri = "https://www.mystore.com/policy"
  tos_uri = "https://www.mystore.com/tos"
  service_documentation= "https://www.mystore.com/doc"
  backchannel_authentication_endpoint = "https://api.mystore.com/ciba"
  supported_backchannel_token_delivery_modes = [ "POLL"]
  backchannel_auth_req_id_duration = 15
  backcannel_polling_interval = 3
  backchannel_user_code_parameter_supported = true
  backchannel_binding_message_required_in_fapi = true
  device_authorization_endpoint = "https://api.mystore.com/device"
  device_verification_uri= "https://api.mystore.com/devverify"
  device_verification_uri_complete= "https://example.com/verification?user_code=USER_CODE"
  device_flow_code_duration = 10
  device_flow_polling_interval = 1
  user_code_charset = "NUMERIC"
  user_code_length= 6
  #supported_trust_frameworks = ["eidas_ial_high"]
  #supported_evidence = ["id_document", "utility_bill"]
  #supported_identity_documents = ["idcard", "password"]
  #supported_verification_methods= ["pipp"]
  #supported_verified_claims = ["given_name"]
  end_session_endpoint = "https://www.mystore.com/endsession"
}

output "api_key" {  
  value = authlete_service.complete_described.id
}
output "api_secret" {  
  value = authlete_service.complete_described.api_secret
}
`

func CheckOutputPresent(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ms := s.RootModule()
		rs, ok := ms.Outputs[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		if rs.Value == nil {
			return fmt.Errorf(
				"Output '%s': expected to have a value, got %#v",
				name,
				rs)
		}

		return nil
	}
}

func getServiceId(*terraform.State) (string, error) {
	return strconv.FormatInt(srvToImport.GetApiKey(), 10), nil
}
