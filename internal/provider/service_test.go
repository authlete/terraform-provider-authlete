package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

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
					CheckOutputPresent("api_key"),
					CheckOutputPresent("api_secret"),
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
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "attribute.*", map[string]string{
						"key":   "high_risk_scopes",
						"value": "scope1 scope2 scope3",
					}),
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "attribute.*", map[string]string{
						"key":   "require_2_fa",
						"value": "true",
					}),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_custom_client_metadata.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_custom_client_metadata.0", "basic_review"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_custom_client_metadata.1", "domain_match"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authentication_callback_endpoint", "https://api.mystore.com/authenticate"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authentication_callback_api_key", "lkjl3k44235kjlk5j43kjdkfslkdf"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authentication_callback_api_secret", "lknasdljjk42j435kjh34jkkjr"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_acrs.#", "2"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_acrs.*", "loa2"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_acrs.*", "loa3"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "developer_authentication_callback_endpoint", "https://api.mystore.com/partner_auth"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "developer_authentication_callback_api_key", "lkjl3k44235kjlk5j43kjdkfslkdf"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "developer_authentication_callback_api_secret", "lknasdljjk42j435kjh34jkkjr"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_grant_types.#", "2"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_grant_types.*", "AUTHORIZATION_CODE"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_grant_types.*", "REFRESH_TOKEN"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_response_types.*", "CODE"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_authorization_detail_types.0", "payment_initiation"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_service_profiles.*", "FAPI"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_service_profiles.*", "OPEN_BANKING"),
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
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "supported_scopes.*", map[string]string{
						"name":          "address",
						"default_entry": "false",
						"description":   "A permission to request an OpenID Provider to include the address claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details.",
					}),
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "supported_scopes.*", map[string]string{
						"name":              "email",
						"default_entry":     "true",
						"description":       "A permission to request an OpenID Provider to include the email claim and the email_verified claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details.",
						"attribute.0.key":   "key1",
						"attribute.0.value": "val1",
					}),

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
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "mtls_endpoint_aliases.*",
						map[string]string{
							"name": "test",
							"uri":  "https://test.com",
						}),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "policy_uri", "https://www.mystore.com/policy"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "tos_uri", "https://www.mystore.com/tos"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "service_documentation", "https://www.mystore.com/doc"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_authentication_endpoint", "https://api.mystore.com/ciba"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_backchannel_token_delivery_modes.0", "POLL"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_auth_req_id_duration", "15"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_polling_interval", "3"),
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
					resource.TestCheckResourceAttr("authlete_service.complete_described", "dcr_duplicate_software_id_blocked", "true"),
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

func TestAccResourceService_update_extended(t *testing.T) {

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
				),
			},
			{
				Config:             testAccResourceServiceUpdateEveryAttribute,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.complete_described", "service_name", "attributes coverage test2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "issuer", "https://test2.com"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "description", "Attributes support test2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "clients_per_developer", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "client_id_alias_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "attribute.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "attribute.*", map[string]string{
						"key":   "high_risk_scopes",
						"value": "scope1 scope2 scope3 scope4",
					}),
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "attribute.*", map[string]string{
						"key":   "require_2_fa",
						"value": "false",
					}),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_custom_client_metadata.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_custom_client_metadata.0", "basic_review2"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_custom_client_metadata.1", "domain_match"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authentication_callback_endpoint", "https://api.mystore.com/authenticate"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authentication_callback_api_key", "lkjl3k44235kjlk5j43kjdkfslkdf"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authentication_callback_api_secret", "lknasdljjk42j435kjh34jkkjr"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_acrs.#", "2"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_acrs.*", "loa2"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_acrs.*", "loa4"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "developer_authentication_callback_endpoint", "https://api.mystore.com/partner_auth"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "developer_authentication_callback_api_key", "lkjl3k44235kjlk5j43kjdkfslkdf"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "developer_authentication_callback_api_secret", "lknasdljjk42j435kjh34jkkjr"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_grant_types.#", "3"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_grant_types.*", "AUTHORIZATION_CODE"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_grant_types.*", "REFRESH_TOKEN"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_response_types.*", "CODE"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_authorization_detail_types.0", "payment_initiation"),
					resource.TestCheckTypeSetElemAttr("authlete_service.complete_described", "supported_service_profiles.*", "FAPI"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "error_description_omitted", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "error_uri_omitted", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authorization_endpoint", "https://api.mystore.com/authorize"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "direct_authorization_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_ui_locales.#", "4"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_displays.#", "1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "pkce_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "pkce_s256_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "authorization_response_duration", "100"),
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
					resource.TestCheckResourceAttr("authlete_service.complete_described", "pushed_auth_req_duration", "100"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "par_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "request_object_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "traditional_request_object_processing_applied", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "nbf_optional", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "front_channel_encryption_request_obj_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "encryption_alg_req_obj_match", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "encryption_enc_alg_req_obj_match", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "access_token_type", "Bearer"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "tls_client_certificate_bound_access_tokens", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "access_token_duration", "990"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "single_access_token_per_subject", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "access_token_sign_alg", "PS256"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "access_token_signature_key_id", "kid1"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "refresh_token_duration", "1500"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "refresh_token_duration_kept", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "refresh_token_duration_reset", "false"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "refresh_token_kept", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "token_expiration_link", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_scopes.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "supported_scopes.*", map[string]string{
						"name":          "address",
						"default_entry": "false",
						"description":   "A permission to request an OpenID Provider to include the address claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details.",
					}),
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "supported_scopes.*", map[string]string{
						"name":              "email",
						"default_entry":     "true",
						"description":       "A permission to request an OpenID Provider to include the email claim and the email_verified claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details.",
						"attribute.0.key":   "key1",
						"attribute.0.value": "val1",
					}),

					resource.TestCheckResourceAttr("authlete_service.complete_described", "scope_required", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "id_token_duration", "980"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "allowable_clock_skew", "10"),
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
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.complete_described", "mtls_endpoint_aliases.*",
						map[string]string{
							"name": "test",
							"uri":  "https://test.com",
						}),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "policy_uri", "https://www.mystore.com/policy"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "tos_uri", "https://www.mystore.com/tos"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "service_documentation", "https://www.mystore.com/doc"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_authentication_endpoint", "https://api.mystore.com/ciba"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "supported_backchannel_token_delivery_modes.0", "POLL"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_auth_req_id_duration", "150"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_polling_interval", "30"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_user_code_parameter_supported", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "backchannel_binding_message_required_in_fapi", "true"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_authorization_endpoint", "https://api.mystore.com/device"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_verification_uri", "https://api.mystore.com/devverify"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_verification_uri_complete", "https://example.com/verification?user_code=USER_CODE"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_flow_code_duration", "100"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "device_flow_polling_interval", "10"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "user_code_charset", "NUMERIC"),
					resource.TestCheckResourceAttr("authlete_service.complete_described", "user_code_length", "3"),
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
					resource.TestCheckResourceAttr("authlete_service.complete_described", "dcr_duplicate_software_id_blocked", "true"),
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

func TestAccResourceService_unordered(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceServiceUnordered,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.prod", "issuer", "https://test.com"),
					CheckOutputPresent("api_key"),
					CheckOutputPresent("api_secret"),
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
