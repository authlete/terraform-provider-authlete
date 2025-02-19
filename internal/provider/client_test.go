package provider

import (
	"testing"

	idp "github.com/authlete/idp-api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestClientDynamicServices(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: stateDynamicServiceState,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_id"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),
				),
			},
			{
				Config: stateDynamicServiceState2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_id"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),
				),
			},
		},
	})
}

func TestClient_pem_cert_support(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: pemSupportClientTests,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_id"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),
					resource.TestCheckResourceAttr("authlete_client.client1", "jwk.#", "1"),
				),
			},
		},
	})
}

func TestClientAllAttributes30(t *testing.T) {

	if testedAuthleteVersionNotBigger("3.0") {
		t.Skip("Skipping test as Authlete version less than 3.0")
		return
	}

	openid := "openid"
	profile := "profile"
	var testService *idp.Service = idp.NewService()
	testService.SetSupportedGrantTypes([]string{
		"AUTHORIZATION_CODE",
		"REFRESH_TOKEN"})
	testService.SetSupportedResponseTypes(
		[]string{"CODE"})
	testService.SupportedScopes = []idp.Scope{
		{
			Name: &openid,
		},
		{
			Name: &profile,
		},
	}
	testService.SetServiceName("Test Service for client testing")
	testService.SetIssuer("https://test.com")
	testService.SetSupportedCustomClientMetadata([]string{"k1", "k2"})
	defer testDestroyTestService(t, testService)
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testCreateTestService(t, testService)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: stateCompleteClientState30,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_id"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),

					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias_enabled", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_type", "CONFIDENTIAL"),
					resource.TestCheckResourceAttr("authlete_client.client1", "redirect_uris.#", "2"),
					resource.TestCheckTypeSetElemAttr("authlete_client.client1", "redirect_uris.*", "https://www.authlete.com/cb"),
					resource.TestCheckTypeSetElemAttr("authlete_client.client1", "redirect_uris.*", "http://localhost:3000/cb"),
					resource.TestCheckResourceAttr("authlete_client.client1", "response_types.#", "2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "grant_types.#", "2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "application_type", "WEB"),
					resource.TestCheckResourceAttr("authlete_client.client1", "contacts.#", "2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_name", "Authlete client"),
					resource.TestCheckResourceAttr("authlete_client.client1", "logo_uri", "https://example.authlete.com/cli/logo.png"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_uri", "https://example.authlete.com/cli/"),
					resource.TestCheckResourceAttr("authlete_client.client1", "policy_uri", "https://example.authlete.com/cli/policy.html"),
					resource.TestCheckResourceAttr("authlete_client.client1", "tos_uri", "https://example.authlete.com/cli/tos.html"),
					resource.TestCheckResourceAttr("authlete_client.client1", "jwks_uri", "https://example.authlete.com/jwks/"),
					resource.TestCheckResourceAttr("authlete_client.client1", "subject_type", "PUBLIC"),
					resource.TestCheckResourceAttr("authlete_client.client1", "id_token_sign_alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "id_token_encryption_alg", "RSA_OAEP_256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "id_token_encryption_enc", "A128CBC_HS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "user_info_sign_alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "user_info_encryption_alg", "RSA_OAEP_256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "user_info_encryption_enc", "A128CBC_HS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_sign_alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_encryption_alg", "RSA_OAEP_256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_encryption_enc", "A128CBC_HS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "token_auth_method", "PRIVATE_KEY_JWT"),
					resource.TestCheckResourceAttr("authlete_client.client1", "token_auth_sign_alg", "ES256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "default_max_age", "123"),
					resource.TestCheckResourceAttr("authlete_client.client1", "default_acrs.#", "2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "auth_time_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "login_uri", "https://login.example.com"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_uris.#", "1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_uris.0", "https://example.authlete.com/cli/req_obj.json"),
					resource.TestCheckResourceAttr("authlete_client.client1", "description", "this is the description of the client"),
					resource.TestCheckResourceAttr("authlete_client.client1", "requestable_scopes_enabled", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "requestable_scopes.0", "openid"),
					resource.TestCheckResourceAttr("authlete_client.client1", "requestable_scopes.1", "profile"),
					resource.TestCheckResourceAttr("authlete_client.client1", "access_token_duration", "100"),
					resource.TestCheckResourceAttr("authlete_client.client1", "refresh_token_duration", "300"),
					resource.TestCheckResourceAttr("authlete_client.client1", "tls_client_auth_subject_dn", "CN=Example, OU=OP, O=Authlete, C=GB"),
					resource.TestCheckResourceAttr("authlete_client.client1", "tls_client_certificate_bound_access_tokens", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "self_signed_certificate_key_id", "kid1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "software_id", "id1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "software_version", "ver1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_sign_alg", "PS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_encryption_alg", "RSA_OAEP_256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_encryption_enc", "A128CBC_HS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "bc_delivery_mode", "PUSH"),
					resource.TestCheckResourceAttr("authlete_client.client1", "bc_notification_endpoint", "https://example.authlete.com/ciba_cb"),
					resource.TestCheckResourceAttr("authlete_client.client1", "bc_request_sign_alg", "PS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "bc_user_code_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "dynamically_registered", "false"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_details_types.0", "str1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_details_types.1", "str2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_details_types.2", "str3"),
					resource.TestCheckResourceAttr("authlete_client.client1", "par_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_object_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "attributes.0.key", "key1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "attributes.1.key", "key2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "attributes.0.value", "val1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "attributes.1.value", "val2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "custom_metadata", "{\"k1\":\"val1\"}"),
					resource.TestCheckResourceAttr("authlete_client.client1", "front_channel_request_object_encryption_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_object_encryption_alg_match_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_object_encryption_enc_match_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "digest_algorithm", "SHA-256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "single_access_token_per_subject", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "pkce_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "pkce_s256_required", "false"),
				),
			},
			{
				ResourceName:            "authlete_client.client1",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"client_id", "client_secret"},
			},
			{
				Config: stateUpdatedClientState30,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_id"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias_enabled", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_type", "CONFIDENTIAL"),
					resource.TestCheckResourceAttr("authlete_client.client1", "redirect_uris.#", "2"),
					resource.TestCheckTypeSetElemAttr("authlete_client.client1", "redirect_uris.*", "https://www.authlete.com/cb"),
					resource.TestCheckTypeSetElemAttr("authlete_client.client1", "redirect_uris.*", "http://localhost:3000/cb"),
					resource.TestCheckResourceAttr("authlete_client.client1", "response_types.#", "2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "grant_types.#", "2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "application_type", "WEB"),
					resource.TestCheckResourceAttr("authlete_client.client1", "contacts.#", "2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_name", "Authlete client"),
					resource.TestCheckResourceAttr("authlete_client.client1", "logo_uri", "https://example.authlete.com/cli/logo.png"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_uri", "https://example.authlete.com/cli/"),
					resource.TestCheckResourceAttr("authlete_client.client1", "policy_uri", "https://example.authlete.com/cli/policy.html"),
					resource.TestCheckResourceAttr("authlete_client.client1", "tos_uri", "https://example.authlete.com/cli/tos.html"),
					resource.TestCheckResourceAttr("authlete_client.client1", "jwks_uri", "https://example.authlete.com/jwks/"),
					resource.TestCheckResourceAttr("authlete_client.client1", "subject_type", "PUBLIC"),
					resource.TestCheckResourceAttr("authlete_client.client1", "id_token_sign_alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "id_token_encryption_alg", "RSA_OAEP_256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "id_token_encryption_enc", "A128CBC_HS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "user_info_sign_alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "user_info_encryption_alg", "RSA_OAEP_256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "user_info_encryption_enc", "A128CBC_HS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_sign_alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_encryption_alg", "RSA_OAEP_256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_encryption_enc", "A128CBC_HS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "token_auth_method", "PRIVATE_KEY_JWT"),
					resource.TestCheckResourceAttr("authlete_client.client1", "token_auth_sign_alg", "ES256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "default_max_age", "123"),
					resource.TestCheckResourceAttr("authlete_client.client1", "default_acrs.#", "2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "auth_time_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "login_uri", "https://login.example.com"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_uris.#", "1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_uris.0", "https://example.authlete.com/cli/req_obj.json"),
					resource.TestCheckResourceAttr("authlete_client.client1", "description", "this is the description of the client"),
					resource.TestCheckResourceAttr("authlete_client.client1", "requestable_scopes_enabled", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "requestable_scopes.0", "openid"),
					resource.TestCheckResourceAttr("authlete_client.client1", "requestable_scopes.1", "profile"),
					resource.TestCheckResourceAttr("authlete_client.client1", "access_token_duration", "100"),
					resource.TestCheckResourceAttr("authlete_client.client1", "refresh_token_duration", "300"),
					resource.TestCheckResourceAttr("authlete_client.client1", "tls_client_auth_subject_dn", "CN=Example, OU=OP, O=Authlete, C=GB"),
					resource.TestCheckResourceAttr("authlete_client.client1", "tls_client_certificate_bound_access_tokens", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "self_signed_certificate_key_id", "kid1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "software_id", "id1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "software_version", "ver1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_sign_alg", "PS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_encryption_alg", "RSA_OAEP_256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_encryption_enc", "A128CBC_HS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "bc_delivery_mode", "PUSH"),
					resource.TestCheckResourceAttr("authlete_client.client1", "bc_notification_endpoint", "https://example.authlete.com/ciba_cb"),
					resource.TestCheckResourceAttr("authlete_client.client1", "bc_request_sign_alg", "PS256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "bc_user_code_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "dynamically_registered", "false"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_details_types.0", "str1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_details_types.1", "str2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "authorization_details_types.2", "str3"),
					resource.TestCheckResourceAttr("authlete_client.client1", "par_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_object_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "attributes.0.key", "key1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "attributes.1.key", "key2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "attributes.0.value", "val1"),
					resource.TestCheckResourceAttr("authlete_client.client1", "attributes.1.value", "val2"),
					resource.TestCheckResourceAttr("authlete_client.client1", "custom_metadata", "{\"k1\":\"val1\"}"),
					resource.TestCheckResourceAttr("authlete_client.client1", "front_channel_request_object_encryption_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_object_encryption_alg_match_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "request_object_encryption_enc_match_required", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "digest_algorithm", "SHA-256"),
					resource.TestCheckResourceAttr("authlete_client.client1", "single_access_token_per_subject", "true"),
					resource.TestCheckResourceAttr("authlete_client.client1", "pkce_required", "false"),
					resource.TestCheckResourceAttr("authlete_client.client1", "pkce_s256_required", "true"),
				),
			},
			{
				ResourceName:            "authlete_client.client1",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"client_id", "client_secret"},
			},
		},
	})
}

func TestClientUnsupportedCustomMetadata(t *testing.T) {
	openid := "openid"
	profile := "profile"
	var testService IService
	testService = idp.NewService()
	testService.(*idp.Service).SetSupportedGrantTypes([]string{
		"AUTHORIZATION_CODE",
		"REFRESH_TOKEN"},
	)
	testService.(*idp.Service).SetSupportedResponseTypes(
		[]string{"CODE"},
	)
	testService.(*idp.Service).SupportedScopes = []idp.Scope{
		{
			Name: &openid,
		},
		{
			Name: &profile,
		},
	}
	
	testService.SetServiceName("Test Service for client testing")
	testService.SetIssuer("https://test.com")
	testService.SetSupportedCustomClientMetadata([]string{"k1", "k2"})
	defer testDestroyTestService(t, testService)
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testCreateTestService(t, testService)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: stateUnsupportedMetadataClientState,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_id"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),

					resource.TestCheckResourceAttr("authlete_client.client1", "custom_metadata", "{\"k2\":\"val2\"}"),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestClient_client_secret_setup(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: clientSecretSupportClientTests,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),
					resource.TestCheckResourceAttr("authlete_client.client1", "client_secret", "terraform_client"),
				),
			},
		},
	})
}
