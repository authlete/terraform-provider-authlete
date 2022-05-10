package provider

import (
	"context"
	"strconv"

	"github.com/authlete/authlete-go-openapi"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func service() *schema.Resource {
	return &schema.Resource{
		Description: `A Service in Authlete platform is mapped to one OIDC Server `,

		CreateContext: serviceCreate,
		ReadContext:   serviceRead,
		UpdateContext: serviceUpdate,
		DeleteContext: serviceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"service_name":                                  {Type: schema.TypeString, Required: true},
			"issuer":                                        {Type: schema.TypeString, Required: true},
			"description":                                   {Type: schema.TypeString, Required: false, Optional: true},
			"api_secret":                                    {Type: schema.TypeString, Computed: true},
			"clients_per_developer":                         {Type: schema.TypeInt, Required: false, Optional: true},
			"client_id_alias_enabled":                       {Type: schema.TypeBool, Required: false, Optional: true, Default: false},
			"attribute":                                     createAttributeSchema(),
			"supported_custom_client_metadata":              createStringColSchema(),
			"authentication_callback_endpoint":              {Type: schema.TypeString, Required: false, Optional: true},
			"authentication_callback_api_key":               {Type: schema.TypeString, Required: false, Optional: true},
			"authentication_callback_api_secret":            {Type: schema.TypeString, Required: false, Optional: true},
			"supported_acrs":                                createStringColSchema(),
			"developer_authentication_callback_endpoint":    {Type: schema.TypeString, Required: false, Optional: true},
			"developer_authentication_callback_api_key":     {Type: schema.TypeString, Required: false, Optional: true},
			"developer_authentication_callback_api_secret":  {Type: schema.TypeString, Required: false, Optional: true},
			"supported_grant_types":                         createGrantTypeSchema(),
			"supported_response_types":                      createResponseTypeSchema(),
			"supported_authorization_detail_types":          createStringColSchema(),
			"supported_service_profiles":                    createSupportedFrameworkSchema(),
			"error_description_omitted":                     {Type: schema.TypeBool, Required: false, Optional: true},
			"error_uri_omitted":                             {Type: schema.TypeBool, Required: false, Optional: true},
			"authorization_endpoint":                        {Type: schema.TypeString, Required: false, Optional: true},
			"direct_authorization_endpoint_enabled":         {Type: schema.TypeBool, Required: false, Optional: true, Default: false},
			"supported_ui_locales":                          createStringColSchema(),
			"supported_displays":                            createSupportedDisplaySchema(),
			"pkce_required":                                 {Type: schema.TypeBool, Required: false, Optional: true},
			"pkce_s256_required":                            {Type: schema.TypeBool, Required: false, Optional: true},
			"authorization_response_duration":               {Type: schema.TypeInt, Required: false, Optional: true},
			"iss_response_suppressed":                       {Type: schema.TypeBool, Required: false, Optional: true},
			"ignore_port_loopback_redirect":                 {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"token_endpoint":                                {Type: schema.TypeString, Required: false, Optional: true},
			"direct_token_endpoint_enabled":                 {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"supported_token_auth_methods":                  createClientAuthSchema(),
			"mutual_tls_validate_pki_cert_chain":            {Type: schema.TypeBool, Required: false, Optional: true},
			"trusted_root_certificates":                     createStringColSchema(),
			"missing_client_id_allowed":                     {Type: schema.TypeBool, Required: false, Optional: true},
			"revocation_endpoint":                           {Type: schema.TypeString, Required: false, Optional: true},
			"direct_revocation_endpoint_enabled":            {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"supported_revocation_auth_methods":             createClientAuthSchema(),
			"introspection_endpoint":                        {Type: schema.TypeString, Required: false, Optional: true},
			"direct_introspection_endpoint_enabled":         {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"supported_introspection_auth_methods":          createClientAuthSchema(),
			"pushed_auth_req_endpoint":                      {Type: schema.TypeString, Required: false, Optional: true},
			"pushed_auth_req_duration":                      {Type: schema.TypeInt, Required: false, Optional: true},
			"par_required":                                  {Type: schema.TypeBool, Required: false, Optional: true},
			"request_object_required":                       {Type: schema.TypeBool, Required: false, Optional: true},
			"traditional_request_object_processing_applied": {Type: schema.TypeBool, Required: false, Optional: true},
			"nbf_optional":                                  {Type: schema.TypeBool, Required: false, Optional: true},
			"front_channel_encryption_request_obj_required": {Type: schema.TypeBool, Required: false, Optional: true},
			"encryption_alg_req_obj_match":                  {Type: schema.TypeBool, Required: false, Optional: true},
			"encryption_enc_alg_req_obj_match":              {Type: schema.TypeBool, Required: false, Optional: true},
			"access_token_type":                             {Type: schema.TypeString, Required: false, Optional: true, Computed: true},
			"tls_client_certificate_bound_access_tokens":    {Type: schema.TypeBool, Required: false, Optional: true},
			"access_token_duration":                         {Type: schema.TypeInt, Required: false, Optional: true},
			"single_access_token_per_subject":               {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"access_token_sign_alg":                         createSignAlgorithmSchema(),
			"access_token_signature_key_id":                 {Type: schema.TypeString, Required: false, Optional: true},
			"refresh_token_duration":                        {Type: schema.TypeInt, Required: false, Optional: true},
			"refresh_token_duration_kept":                   {Type: schema.TypeBool, Required: false, Optional: true},
			"refresh_token_duration_reset":                  {Type: schema.TypeBool, Required: false, Optional: true},
			"refresh_token_kept":                            {Type: schema.TypeBool, Required: false, Optional: true},
			"token_expiration_link":                         {Type: schema.TypeBool, Required: false, Optional: true},
			"supported_scopes":                              createSupportedScopeSchema(),
			"scope_required":                                {Type: schema.TypeBool, Required: false, Optional: true},
			"id_token_duration":                             {Type: schema.TypeInt, Required: false, Optional: true},
			"allowable_clock_skew":                          {Type: schema.TypeInt, Required: false, Optional: true},
			"supported_claim_types":                         createSupportedClaimTypesSchema(),
			"supported_claim_locales":                       createStringColSchema(),
			"supported_claims":                              createStringColSchema(),
			"claim_shortcut_restrictive":                    {Type: schema.TypeBool, Required: false, Optional: true},
			"jwks_endpoint":                                 {Type: schema.TypeString, Required: false, Optional: true},
			"direct_jwks_endpoint_enabled":                  {Type: schema.TypeBool, Required: false, Optional: true, Default: false},
			"jwk":                                           createJWKSchema(),
			"id_token_signature_key_id":                     {Type: schema.TypeString, Required: false, Optional: true},
			"user_info_signature_key_id":                    {Type: schema.TypeString, Required: false, Optional: true},
			"authorization_signature_key_id":                {Type: schema.TypeString, Required: false, Optional: true},
			"hsm_enabled":                                   {Type: schema.TypeBool, Required: false, Optional: true},
			"user_info_endpoint":                            {Type: schema.TypeString, Required: false, Optional: true},
			"direct_user_info_endpoint_enabled":             {Type: schema.TypeBool, Required: false, Optional: true, Default: false},
			"dynamic_registration_supported":                {Type: schema.TypeBool, Required: false, Optional: true},
			"dcr_scope_used_as_requestable":                 {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"registration_endpoint":                         {Type: schema.TypeString, Required: false, Optional: true},
			"registration_management_endpoint":              {Type: schema.TypeString, Required: false, Optional: true},
			"mtls_endpoint_aliases":                         createMtlsEndpointSchema(),
			"policy_uri":                                    {Type: schema.TypeString, Required: false, Optional: true},
			"tos_uri":                                       {Type: schema.TypeString, Required: false, Optional: true},
			"service_documentation":                         {Type: schema.TypeString, Required: false, Optional: true},
			"backchannel_authentication_endpoint":           {Type: schema.TypeString, Required: false, Optional: true},
			"supported_backchannel_token_delivery_modes":    createBackchannelDeliverySchema(),
			"backchannel_auth_req_id_duration":              {Type: schema.TypeInt, Required: false, Optional: true},
			"backcannel_polling_interval":                   {Type: schema.TypeInt, Required: false, Optional: true},
			"backchannel_user_code_parameter_supported":     {Type: schema.TypeBool, Required: false, Optional: true},
			"backchannel_binding_message_required_in_fapi":  {Type: schema.TypeBool, Required: false, Optional: true},
			"device_authorization_endpoint":                 {Type: schema.TypeString, Required: false, Optional: true},
			"device_verification_uri":                       {Type: schema.TypeString, Required: false, Optional: true},
			"device_verification_uri_complete":              {Type: schema.TypeString, Required: false, Optional: true},
			"device_flow_code_duration":                     {Type: schema.TypeInt, Required: false, Optional: true},
			"device_flow_polling_interval":                  {Type: schema.TypeInt, Required: false, Optional: true},
			"user_code_charset":                             createUserCodeCharsetSchema(),
			"user_code_length":                              {Type: schema.TypeInt, Required: false, Optional: true},
			/*
				"supported_trust_frameworks":                    createStringColSchema(),
				"supported_evidence":                            createStringColSchema(),
				"supported_identity_documents":                  createStringColSchema(),
				"supported_verification_methods":                createStringColSchema(),
				"supported_verified_claims":                     createStringColSchema(),
			*/

			"end_session_endpoint": {Type: schema.TypeString, Required: false, Optional: true},
		},
	}
}

func serviceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	client := meta.(*apiClient)

	var diags diag.Diagnostics

	tflog.Trace(ctx, "Creating a new service")

	newServiceDto, diags := dataToService(d, diags)
	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: client.service_owner_key,
		Password: client.service_owner_secret,
	})
	r, _, err := client.authleteClient.ServiceManagementApi.ServiceCreateApi(auth).Service(*newServiceDto).Execute()

	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Service created")

	api_key := r.ApiKey
	api_secret := r.ApiSecret

	// populate the state with default values coming from authlete api server.
	diags = serviceToResource(r, d)

	d.SetId(strconv.FormatInt(*api_key, 10))
	d.Set("api_secret", api_secret)

	return diags

}

func serviceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	return serviceReadInternal(ctx, d, meta, diags)
}

func serviceReadInternal(ctx context.Context, d *schema.ResourceData, meta interface{}, diags diag.Diagnostics) diag.Diagnostics {
	client := meta.(*apiClient)

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: client.service_owner_key,
		Password: client.service_owner_secret,
	})
	dto, _, err := client.authleteClient.ServiceManagementApi.ServiceGetApi(auth, d.Id()).Execute()

	if err != nil {
		return diag.FromErr(err)
	}
	diags = serviceToResource(dto, d)

	return diags
}

func serviceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics

	client := meta.(*apiClient)

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: client.service_owner_key,
		Password: client.service_owner_secret,
	})
	srv, _, err := client.authleteClient.ServiceManagementApi.ServiceGetApi(auth, d.Id()).Execute()

	if err != nil {
		return diag.FromErr(err)
	}

	if d.HasChange("service_name") {
		srv.SetServiceName(d.Get("service_name").(string))
	}
	if d.HasChange("issuer") {
		srv.SetIssuer(d.Get("issuer").(string))
	}
	if d.HasChange("description") {
		srv.SetDescription(d.Get("description").(string))
	}
	if d.HasChange("clients_per_developer") {
		srv.SetClientsPerDeveloper(int32(d.Get("clients_per_developer").(uint16)))
	}
	if d.HasChange("client_id_alias_enabled") {
		srv.SetClientIdAliasEnabled(d.Get("client_id_alias_enabled").(bool))
	}
	if d.HasChange("attributes") {
		srv.Attributes = mapAttributesToDTO(d.Get("attribute").([]interface{}))
	}
	if d.HasChange("supported_custom_client_metadata") {
		srv.SetSupportedCustomClientMetadata(mapSetToString(d.Get("supported_custom_client_metadata").([]interface{})))
	}
	if d.HasChange("authentication_callback_endpoint") {
		srv.SetAuthenticationCallbackEndpoint(d.Get("authentication_callback_endpoint").(string))
	}
	if d.HasChange("authentication_callback_api_key") {
		srv.SetAuthenticationCallbackApiKey(d.Get("authentication_callback_api_key").(string))
	}
	if d.HasChange("authentication_callback_api_secret") {
		srv.SetAuthenticationCallbackApiSecret(d.Get("authentication_callback_api_secret").(string))
	}
	if d.HasChange("supported_acrs") {
		srv.SetSupportedAcrs(mapSetToString(d.Get("supported_acrs").([]interface{})))
	}
	if d.HasChange("developer_authentication_callback_endpoint") {
		srv.SetDeveloperAuthenticationCallbackEndpoint(d.Get("developer_authentication_callback_endpoint").(string))
	}
	if d.HasChange("developer_authentication_callback_api_key") {
		srv.SetDeveloperAuthenticationCallbackApiKey(d.Get("developer_authentication_callback_api_key").(string))
	}
	if d.HasChange("developer_authentication_callback_api_secret") {
		srv.SetDeveloperAuthenticationCallbackApiSecret(d.Get("developer_authentication_callback_api_secret").(string))
	}

	if d.HasChange("supported_grant_types") {
		srv.SetSupportedGrantTypes(mapGrantTypesToDTO(d.Get("supported_grant_types").([]interface{})))
	}
	if d.HasChange("supported_response_types") {
		srv.SetSupportedResponseTypes(mapResponseTypesToDTO(d.Get("supported_response_types").([]interface{})))
	}
	if d.HasChange("supported_authorization_detail_types") {
		srv.SetSupportedAuthorizationDetailsTypes(mapSetToString(d.Get("supported_authorization_detail_types").([]interface{})))
	}
	if d.HasChange("supported_service_profiles") {
		srv.SetSupportedServiceProfiles(mapSupportedFrameworkToDTO(d.Get("supported_service_profiles").([]interface{})))
	}
	if d.HasChange("error_description_omitted") {
		srv.SetErrorDescriptionOmitted(d.Get("error_description_omitted").(bool))
	}
	if d.HasChange("error_uri_omitted") {
		srv.SetErrorUriOmitted(d.Get("error_uri_omitted").(bool))
	}
	if d.HasChange("authorization_endpoint") {
		srv.SetAuthorizationEndpoint(d.Get("authorization_endpoint").(string))
	}
	if d.HasChange("direct_authorization_endpoint_enabled") {
		srv.SetDirectAuthorizationEndpointEnabled(d.Get("direct_authorization_endpoint_enabled").(bool))
	}
	if d.HasChange("supported_ui_locales") {
		srv.SetSupportedUiLocales(mapSetToString(d.Get("supported_ui_locales").([]interface{})))
	}
	if d.HasChange("supported_displays") {
		srv.SetSupportedDisplays(mapSupportedDisplayToDTO(d.Get("supported_displays").([]interface{})))
	}
	if d.HasChange("pkce_required") {
		srv.SetPkceRequired(d.Get("pkce_required").(bool))
	}
	if d.HasChange("pkce_s256_required") {
		srv.SetPkceS256Required(d.Get("pkce_s256_required").(bool))
	}
	if d.HasChange("authorization_response_duration") {
		srv.SetAuthorizationResponseDuration(int64(d.Get("authorization_response_duration").(int)))
	}
	if d.HasChange("iss_response_parameter") {
		srv.SetIssSuppressed(d.Get("iss_response_suppressed").(bool))
	}
	/*if d.HasChange("ignore_port_loopback_redirect") {
		srv.SetLoopbackRedirectionUriVariable(d.Get("ignore_port_loopback_redirect").(bool))
	}
	*/

	if d.HasChange("token_endpoint") {
		srv.SetTokenEndpoint(d.Get("token_endpoint").(string))
	}
	if d.HasChange("direct_token_endpoint_enabled") {
		srv.SetDirectTokenEndpointEnabled(d.Get("direct_token_endpoint_enabled").(bool))
	}
	if d.HasChange("supported_token_auth_methods") {
		srv.SetSupportedTokenAuthMethods(mapClientAuthMethods(d.Get("supported_token_auth_methods").([]interface{})))
	}
	if d.HasChange("mutual_tls_validate_pki_cert_chain") {
		srv.SetMutualTlsValidatePkiCertChain(d.Get("mutual_tls_validate_pki_cert_chain").(bool))
	}
	if d.HasChange("trusted_root_certificates") {
		srv.SetTrustedRootCertificates(mapSetToString(d.Get("trusted_root_certificates").([]interface{})))
	}
	if d.HasChange("missing_client_id_allowed") {
		srv.SetMissingClientIdAllowed(d.Get("missing_client_id_allowed").(bool))
	}
	if d.HasChange("revocation_endpoint") {
		srv.SetRevocationEndpoint(d.Get("revocation_endpoint").(string))
	}
	if d.HasChange("direct_revocation_endpoint_enabled") {
		srv.SetDirectRevocationEndpointEnabled(d.Get("direct_revocation_endpoint_enabled").(bool))
	}
	if d.HasChange("supported_revocation_auth_methods") {
		srv.SetSupportedRevocationAuthMethods(mapClientAuthMethods(d.Get("supported_revocation_auth_methods").([]interface{})))
	}
	if d.HasChange("introspection_endpoint") {
		srv.SetIntrospectionEndpoint(d.Get("introspection_endpoint").(string))
	}
	if d.HasChange("direct_introspection_endpoint_enabled") {
		srv.SetDirectIntrospectionEndpointEnabled(d.Get("direct_introspection_endpoint_enabled").(bool))
	}
	if d.HasChange("supported_introspection_auth_methods") {
		srv.SetSupportedIntrospectionAuthMethods(mapClientAuthMethods(d.Get("supported_introspection_auth_methods").([]interface{})))
	}
	if d.HasChange("pushed_auth_req_endpoint") {
		srv.SetPushedAuthReqEndpoint(d.Get("pushed_auth_req_endpoint").(string))
	}
	if d.HasChange("pushed_auth_req_duration") {
		srv.SetPushedAuthReqDuration(int64(d.Get("pushed_auth_req_duration").(int)))
	}
	if d.HasChange("par_required") {
		srv.SetParRequired(d.Get("par_required").(bool))
	}
	if d.HasChange("request_object_required") {
		srv.SetRequestObjectRequired(d.Get("request_object_required").(bool))
	}
	if d.HasChange("traditional_request_object_processing_applied") {
		srv.SetTraditionalRequestObjectProcessingApplied(d.Get("traditional_request_object_processing_applied").(bool))
	}
	if d.HasChange("nbf_optional") {
		srv.SetNbfOptional(d.Get("nbf_optional").(bool))
	}
	if d.HasChange("front_channel_encryption_request_obj_required") {
		srv.SetFrontChannelRequestObjectEncryptionRequired(d.Get("front_channel_encryption_request_obj_required").(bool))
	}
	if d.HasChange("encryption_alg_req_obj_match") {
		srv.SetRequestObjectEncryptionAlgMatchRequired(d.Get("encryption_alg_req_obj_match").(bool))
	}
	if d.HasChange("encryption_enc_alg_req_obj_match") {
		srv.SetRequestObjectEncryptionEncMatchRequired(d.Get("encryption_enc_alg_req_obj_match").(bool))
	}
	if d.HasChange("access_token_type") {
		srv.SetAccessTokenType(d.Get("access_token_type").(string))
	}
	if d.HasChange("single_access_token_per_subject") {
		srv.SetSingleAccessTokenPerSubject(d.Get("single_access_token_per_subject").(bool))
	}

	if d.HasChange("access_token_sign_alg") {
		srv.SetAccessTokenSignAlg(mapSignAlgorithms(d.Get("access_token_sign_alg").(string)))
	}
	if d.HasChange("access_token_signature_key_id") {
		srv.SetAccessTokenSignatureKeyId(d.Get("access_token_signature_key_id").(string))
	}
	if d.HasChange("refresh_token_duration") {
		srv.SetRefreshTokenDuration(int64(d.Get("refresh_token_duration").(int)))
	}
	if d.HasChange("refresh_token_duration_kept") {
		srv.SetRefreshTokenDurationKept(d.Get("refresh_token_duration_kept").(bool))
	}
	if d.HasChange("refresh_token_duration_reset") {
		srv.SetRefreshTokenDurationReset(d.Get("refresh_token_duration_reset").(bool))
	}
	if d.HasChange("refresh_token_kept") {
		srv.SetRefreshTokenKept(d.Get("refresh_token_kept").(bool))
	}
	if d.HasChange("token_expiration_link") {
		srv.SetTokenExpirationLinked(d.Get("token_expiration_link").(bool))
	}
	if d.HasChange("supported_scopes") {
		srv.SetSupportedScopes(mapSupportedScopeToDTO(d.Get("supported_scopes").([]interface{})))
	}
	if d.HasChange("scope_required") {
		srv.SetScopeRequired(d.Get("scope_required").(bool))
	}
	if d.HasChange("id_token_duration") {
		srv.SetIdTokenDuration(int64(d.Get("id_token_duration").(int)))
	}
	if d.HasChange("allowable_clock_skew") {
		srv.SetAllowableClockSkew(int32(d.Get("allowable_clock_skew").(int)))
	}
	if d.HasChange("supported_claim_types") {
		srv.SetSupportedClaimTypes(mapClaimTypesToDTO(d.Get("supported_claim_types").([]interface{})))
	}
	if d.HasChange("supported_claim_locales") {
		srv.SetSupportedClaimLocales(mapSetToString(d.Get("supported_claim_locales").([]interface{})))
	}
	if d.HasChange("supported_claims") {
		srv.SetSupportedClaims(mapSetToString(d.Get("supported_claims").([]interface{})))
	}
	if d.HasChange("claim_shortcut_restrictive") {
		srv.SetClaimShortcutRestrictive(d.Get("claim_shortcut_restrictive").(bool))
	}
	if d.HasChange("jwks_endpoint") {
		srv.SetJwksUri(d.Get("jwks_endpoint").(string))
	}
	if d.HasChange("direct_jwks_endpoint_enabled") {
		srv.SetDirectJwksEndpointEnabled(d.Get("direct_jwks_endpoint_enabled").(bool))
	}
	if d.HasChange("jwk") {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Updating JWK",
			Detail:   "Updating JWK ",
		})

		jwks, _ := updateJWKS(d.Get("jwk").([]interface{}), srv.GetJwks(), diags)
		srv.SetJwks(jwks)
	}

	if d.HasChange("id_token_signature_key_id") {
		srv.SetIdTokenSignatureKeyId(d.Get("id_token_signature_key_id").(string))
	}
	if d.HasChange("user_info_signature_key_id") {
		srv.SetUserInfoSignatureKeyId(d.Get("user_info_signature_key_id").(string))
	}
	if d.HasChange("authorization_signature_key_id") {
		srv.SetAuthorizationSignatureKeyId(d.Get("authorization_signature_key_id").(string))
	}
	if d.HasChange("hsm_enabled") {
		srv.SetHsmEnabled(d.Get("hsm_enabled").(bool))
	}
	if d.HasChange("user_info_endpoint") {
		srv.SetUserInfoEndpoint(d.Get("user_info_endpoint").(string))
	}
	if d.HasChange("direct_user_info_endpoint_enabled") {
		srv.SetDirectUserInfoEndpointEnabled(d.Get("direct_user_info_endpoint_enabled").(bool))
	}
	if d.HasChange("dynamic_registration_supported") {
		srv.SetDynamicRegistrationSupported(d.Get("dynamic_registration_supported").(bool))
	}
	/*if d.HasChange("dcr_scope_used_as_requestable") {
		srv.SetDcrScopeUsedAsRequestable(d.Get("dcr_scope_used_as_requestable").(bool))
	}
	*/
	if d.HasChange("registration_endpoint") {
		srv.SetRegistrationEndpoint(d.Get("registration_endpoint").(string))
	}
	if d.HasChange("registration_management_endpoint") {
		srv.SetRegistrationManagementEndpoint(d.Get("registration_management_endpoint").(string))
	}
	if d.HasChange("mtls_endpoint_aliases") {
		srv.SetMtlsEndpointAliases(mapMtlsEndpoint(d.Get("mtls_endpoint_aliases").([]interface{})))
	}
	if d.HasChange("policy_uri") {
		srv.SetPolicyUri(d.Get("policy_uri").(string))
	}
	if d.HasChange("tos_uri") {
		srv.SetTosUri(d.Get("tos_uri").(string))
	}
	if d.HasChange("service_documentation") {
		srv.SetServiceDocumentation(d.Get("service_documentation").(string))
	}
	if d.HasChange("backchannel_authentication_endpoint") {
		srv.SetBackchannelAuthenticationEndpoint(d.Get("backchannel_authentication_endpoint").(string))
	}
	if d.HasChange("supported_backchannel_token_delivery_modes") {
		srv.SetSupportedBackchannelTokenDeliveryModes(mapBackchannelDelivery(d.Get("supported_backchannel_token_delivery_modes").([]interface{})))
	}
	if d.HasChange("backchannel_auth_req_id_duration") {
		srv.SetBackchannelAuthReqIdDuration(int32(d.Get("backchannel_auth_req_id_duration").(int)))
	}
	if d.HasChange("backcannel_polling_interval") {
		srv.SetBackchannelPollingInterval(int32(d.Get("backcannel_polling_interval").(int)))
	}
	if d.HasChange("backchannel_user_code_parameter_supported") {
		srv.SetBackchannelUserCodeParameterSupported(d.Get("backchannel_user_code_parameter_supported").(bool))
	}
	if d.HasChange("backchannel_binding_message_required_in_fapi") {
		srv.SetBackchannelBindingMessageRequiredInFapi(d.Get("backchannel_binding_message_required_in_fapi").(bool))
	}
	if d.HasChange("device_authorization_endpoint") {
		srv.SetDeviceAuthorizationEndpoint(d.Get("device_authorization_endpoint").(string))
	}
	if d.HasChange("device_verification_uri") {
		srv.SetDeviceVerificationUri(d.Get("device_verification_uri").(string))
	}
	if d.HasChange("device_verification_uri_complete") {
		srv.SetDeviceVerificationUriComplete(d.Get("device_verification_uri_complete").(string))
	}
	if d.HasChange("device_flow_code_duration") {
		srv.SetDeviceFlowCodeDuration(int32(d.Get("device_flow_code_duration").(int)))
	}
	if d.HasChange("device_flow_polling_interval") {
		srv.SetDeviceFlowPollingInterval(int32(d.Get("device_flow_polling_interval").(int)))
	}
	if d.HasChange("user_code_charset") {
		srv.SetUserCodeCharset(mapUserCodeCharsets(d.Get("user_code_charset").(string)))
	}
	if d.HasChange("user_code_length") {
		srv.SetUserCodeLength(int32(d.Get("user_code_length").(int)))
	}
	/*
		if d.HasChange("supported_trust_frameworks") {
			srv.SetSupportedTrustFrameworks(mapSetToString(d.Get("supported_trust_frameworks").(*schema.Set)))
		}
		if d.HasChange("supported_evidence") {
			srv.SetSupportedEvidence(mapSetToString(d.Get("supported_evidence").(*schema.Set)))
		}
		if d.HasChange("supported_identity_documents") {
			srv.SetSupportedIdentityDocuments(mapSetToString(d.Get("supported_identity_documents").(*schema.Set)))
		}
		if d.HasChange("supported_verification_methods") {
			srv.SetSupportedVerificationMethods(mapSetToString(d.Get("supported_verification_methods").(*schema.Set)))
		}
		if d.HasChange("supported_verified_claims") {
			srv.SetSupportedVerifiedClaims(mapSetToString(d.Get("supported_verified_claims").(*schema.Set)))
		}
	*/
	if d.HasChange("end_session_endpoint") {
		srv.SetEndSessionEndpoint(d.Get("end_session_endpoint").(string))
	}

	_, _, err = client.authleteClient.ServiceManagementApi.ServiceUpdateApi(auth, d.Id()).Service(*srv).Execute()

	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func serviceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	// client := meta.(*apiClient)

	client := meta.(*apiClient)

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: client.service_owner_key,
		Password: client.service_owner_secret,
	})

	_, err := client.authleteClient.ServiceManagementApi.ServiceDeleteApi(auth, d.Id()).Execute()

	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func dataToService(data *schema.ResourceData, diags diag.Diagnostics) (*authlete.Service, diag.Diagnostics) {

	newServiceDto := authlete.Service{}

	if NotZeroString(data, "service_name") {
		newServiceDto.SetServiceName(data.Get("service_name").(string))
	}
	if NotZeroString(data, "issuer") {
		newServiceDto.SetIssuer(data.Get("issuer").(string))
	}
	if NotZeroString(data, "description") {
		newServiceDto.SetDescription(data.Get("description").(string))
	}
	if NotZeroNumber(data, "clients_per_developer") {
		newServiceDto.SetClientsPerDeveloper(int32(data.Get("clients_per_developer").(int)))
	}
	newServiceDto.SetClientIdAliasEnabled(data.Get("client_id_alias_enabled").(bool))
	if NotZeroArray(data, "attribute") {
		newServiceDto.SetAttributes(mapAttributesToDTO(data.Get("attribute").([]interface{})))
	}
	if NotZeroArray(data, "supported_custom_client_metadata") {
		newServiceDto.SetSupportedCustomClientMetadata(mapSetToString(data.Get("supported_custom_client_metadata").([]interface{})))
	}
	if NotZeroString(data, "authentication_callback_endpoint") {
		newServiceDto.SetAuthenticationCallbackEndpoint(data.Get("authentication_callback_endpoint").(string))
	}
	if NotZeroString(data, "authentication_callback_api_key") {
		newServiceDto.SetAuthenticationCallbackApiKey(data.Get("authentication_callback_api_key").(string))
	}
	if NotZeroString(data, "authentication_callback_api_secret") {
		newServiceDto.SetAuthenticationCallbackApiSecret(data.Get("authentication_callback_api_secret").(string))
	}
	if NotZeroArray(data, "supported_acrs") {
		newServiceDto.SetSupportedAcrs(mapSetToString(data.Get("supported_acrs").([]interface{})))
	}
	if NotZeroString(data, "developer_authentication_callback_endpoint") {
		newServiceDto.SetDeveloperAuthenticationCallbackEndpoint(data.Get("developer_authentication_callback_endpoint").(string))
	}
	if NotZeroString(data, "developer_authentication_callback_api_key") {
		newServiceDto.SetDeveloperAuthenticationCallbackApiKey(data.Get("developer_authentication_callback_api_key").(string))
	}
	if NotZeroString(data, "developer_authentication_callback_api_secret") {
		newServiceDto.SetDeveloperAuthenticationCallbackApiSecret(data.Get("developer_authentication_callback_api_secret").(string))
	}
	if NotZeroArray(data, "supported_grant_types") {
		newServiceDto.SetSupportedGrantTypes(mapGrantTypesToDTO(data.Get("supported_grant_types").([]interface{})))
	}
	if NotZeroArray(data, "supported_response_types") {
		newServiceDto.SetSupportedResponseTypes(mapResponseTypesToDTO(data.Get("supported_response_types").([]interface{})))
	}
	if NotZeroArray(data, "supported_authorization_detail_types") {
		newServiceDto.SetSupportedAuthorizationDetailsTypes(mapSetToString(data.Get("supported_authorization_detail_types").([]interface{})))
	}
	if NotZeroArray(data, "supported_service_profiles") {
		newServiceDto.SetSupportedServiceProfiles(mapSupportedFrameworkToDTO(data.Get("supported_service_profiles").([]interface{})))
	}
	newServiceDto.SetErrorDescriptionOmitted(data.Get("error_description_omitted").(bool))
	newServiceDto.SetErrorUriOmitted(data.Get("error_uri_omitted").(bool))
	if NotZeroString(data, "authorization_endpoint") {
		newServiceDto.SetAuthorizationEndpoint(data.Get("authorization_endpoint").(string))
	}
	newServiceDto.SetDirectAuthorizationEndpointEnabled(data.Get("direct_authorization_endpoint_enabled").(bool))
	if NotZeroArray(data, "supported_ui_locales") {
		newServiceDto.SetSupportedUiLocales(mapSetToString(data.Get("supported_ui_locales").([]interface{})))
	}
	if NotZeroArray(data, "supported_displays") {
		newServiceDto.SetSupportedDisplays(mapSupportedDisplayToDTO(data.Get("supported_displays").([]interface{})))
	}
	newServiceDto.SetPkceRequired(data.Get("pkce_required").(bool))
	newServiceDto.SetPkceS256Required(data.Get("pkce_s256_required").(bool))
	if NotZeroNumber(data, "authorization_response_duration") {
		newServiceDto.SetAuthorizationResponseDuration(int64(data.Get("authorization_response_duration").(int)))
	}
	newServiceDto.SetIssSuppressed(data.Get("iss_response_suppressed").(bool))
	// newServiceDto.SetLoopbackRedirectionUriVariable(data.Get("ignore_port_loopback_redirect").(bool))
	if NotZeroString(data, "token_endpoint") {
		newServiceDto.SetTokenEndpoint(data.Get("token_endpoint").(string))
	}
	newServiceDto.SetDirectTokenEndpointEnabled(data.Get("direct_token_endpoint_enabled").(bool))
	if NotZeroArray(data, "supported_token_auth_methods") {
		newServiceDto.SetSupportedTokenAuthMethods(mapClientAuthMethods(data.Get("supported_token_auth_methods").([]interface{})))
	}
	newServiceDto.SetMutualTlsValidatePkiCertChain(data.Get("mutual_tls_validate_pki_cert_chain").(bool))
	if NotZeroArray(data, "trusted_root_certificates") {
		newServiceDto.SetTrustedRootCertificates(mapSetToString(data.Get("trusted_root_certificates").([]interface{})))
	}
	newServiceDto.SetMissingClientIdAllowed(data.Get("missing_client_id_allowed").(bool))
	if NotZeroString(data, "revocation_endpoint") {
		newServiceDto.SetRevocationEndpoint(data.Get("revocation_endpoint").(string))
	}
	newServiceDto.SetDirectRevocationEndpointEnabled(data.Get("direct_revocation_endpoint_enabled").(bool))
	if NotZeroArray(data, "supported_revocation_auth_methods") {
		newServiceDto.SetSupportedRevocationAuthMethods(mapClientAuthMethods(data.Get("supported_revocation_auth_methods").([]interface{})))
	}
	if NotZeroString(data, "introspection_endpoint") {
		newServiceDto.SetIntrospectionEndpoint(data.Get("introspection_endpoint").(string))
	}
	newServiceDto.SetDirectIntrospectionEndpointEnabled(data.Get("direct_introspection_endpoint_enabled").(bool))
	if NotZeroArray(data, "supported_introspection_auth_methods") {
		newServiceDto.SetSupportedIntrospectionAuthMethods(mapClientAuthMethods(data.Get("supported_introspection_auth_methods").([]interface{})))
	}
	if NotZeroString(data, "pushed_auth_req_endpoint") {
		newServiceDto.SetPushedAuthReqEndpoint(data.Get("pushed_auth_req_endpoint").(string))
	}
	if NotZeroNumber(data, "pushed_auth_req_duration") {
		newServiceDto.SetPushedAuthReqDuration(int64(data.Get("pushed_auth_req_duration").(int)))
	}
	newServiceDto.SetParRequired(data.Get("par_required").(bool))
	newServiceDto.SetRequestObjectRequired(data.Get("request_object_required").(bool))
	newServiceDto.SetTraditionalRequestObjectProcessingApplied(data.Get("traditional_request_object_processing_applied").(bool))
	newServiceDto.SetNbfOptional(data.Get("nbf_optional").(bool))
	newServiceDto.SetFrontChannelRequestObjectEncryptionRequired(data.Get("front_channel_encryption_request_obj_required").(bool))
	newServiceDto.SetRequestObjectEncryptionAlgMatchRequired(data.Get("encryption_alg_req_obj_match").(bool))
	newServiceDto.SetRequestObjectEncryptionEncMatchRequired(data.Get("encryption_enc_alg_req_obj_match").(bool))
	if NotZeroString(data, "access_token_type") {
		newServiceDto.SetAccessTokenType(data.Get("access_token_type").(string))
	}
	newServiceDto.SetTlsClientCertificateBoundAccessTokens(data.Get("tls_client_certificate_bound_access_tokens").(bool))
	if NotZeroNumber(data, "access_token_duration") {
		newServiceDto.SetAccessTokenDuration(int64(data.Get("access_token_duration").(int)))
	}
	newServiceDto.SetSingleAccessTokenPerSubject(data.Get("single_access_token_per_subject").(bool))
	if NotZeroString(data, "access_token_sign_alg") {
		newServiceDto.SetAccessTokenSignAlg(mapSignAlgorithms(data.Get("access_token_sign_alg").(string)))
	}
	if NotZeroString(data, "access_token_signature_key_id") {
		newServiceDto.SetAccessTokenSignatureKeyId(data.Get("access_token_signature_key_id").(string))
	}
	if NotZeroNumber(data, "refresh_token_duration") {
		newServiceDto.SetRefreshTokenDuration(int64(data.Get("refresh_token_duration").(int)))
	}
	newServiceDto.SetRefreshTokenDurationKept(data.Get("refresh_token_duration_kept").(bool))
	newServiceDto.SetRefreshTokenDurationReset(data.Get("refresh_token_duration_reset").(bool))
	newServiceDto.SetRefreshTokenKept(data.Get("refresh_token_kept").(bool))
	newServiceDto.SetTokenExpirationLinked(data.Get("token_expiration_link").(bool))
	if NotZeroArray(data, "supported_scopes") {
		newServiceDto.SetSupportedScopes(mapSupportedScopeToDTO(data.Get("supported_scopes").([]interface{})))
	}
	newServiceDto.SetScopeRequired(data.Get("scope_required").(bool))
	if NotZeroNumber(data, "id_token_duration") {
		newServiceDto.SetIdTokenDuration(int64(data.Get("id_token_duration").(int)))
	}
	if NotZeroNumber(data, "allowable_clock_skew") {
		newServiceDto.SetAllowableClockSkew(int32(data.Get("allowable_clock_skew").(int)))
	}
	if NotZeroArray(data, "supported_claim_types") {
		newServiceDto.SetSupportedClaimTypes(mapClaimTypesToDTO(data.Get("supported_claim_types").([]interface{})))
	}
	if NotZeroArray(data, "supported_claim_locales") {
		newServiceDto.SetSupportedClaimLocales(mapSetToString(data.Get("supported_claim_locales").([]interface{})))
	}
	if NotZeroArray(data, "supported_claims") {
		newServiceDto.SetSupportedClaims(mapSetToString(data.Get("supported_claims").([]interface{})))
	}
	newServiceDto.SetClaimShortcutRestrictive(data.Get("claim_shortcut_restrictive").(bool))
	if NotZeroString(data, "jwks_endpoint") {
		newServiceDto.SetJwksUri(data.Get("jwks_endpoint").(string))
	}
	newServiceDto.SetDirectJwksEndpointEnabled(data.Get("direct_jwks_endpoint_enabled").(bool))
	if NotZeroArray(data, "jwk") {
		var jwk string
		jwk, diags = mapJWKS(data.Get("jwk").([]interface{}), diags)
		newServiceDto.SetJwks(jwk)
	}
	if NotZeroString(data, "id_token_signature_key_id") {
		newServiceDto.SetIdTokenSignatureKeyId(data.Get("id_token_signature_key_id").(string))
	}
	if NotZeroString(data, "user_info_signature_key_id") {
		newServiceDto.SetUserInfoSignatureKeyId(data.Get("user_info_signature_key_id").(string))
	}
	if NotZeroString(data, "authorization_signature_key_id") {
		newServiceDto.SetAuthorizationSignatureKeyId(data.Get("authorization_signature_key_id").(string))
	}
	newServiceDto.SetHsmEnabled(data.Get("hsm_enabled").(bool))

	if NotZeroString(data, "user_info_endpoint") {
		newServiceDto.SetUserInfoEndpoint(data.Get("user_info_endpoint").(string))
	}
	newServiceDto.SetDirectUserInfoEndpointEnabled(data.Get("direct_user_info_endpoint_enabled").(bool))
	newServiceDto.SetDynamicRegistrationSupported(data.Get("dynamic_registration_supported").(bool))
	newServiceDto.SetDcrScopeUsedAsRequestable(data.Get("dcr_scope_used_as_requestable").(bool))
	if NotZeroString(data, "registration_endpoint") {
		newServiceDto.SetRegistrationEndpoint(data.Get("registration_endpoint").(string))
	}
	if NotZeroString(data, "registration_management_endpoint") {
		newServiceDto.SetRegistrationManagementEndpoint(data.Get("registration_management_endpoint").(string))
	}
	if NotZeroArray(data, "mtls_endpoint_aliases") {
		newServiceDto.SetMtlsEndpointAliases(mapMtlsEndpoint(data.Get("mtls_endpoint_aliases").([]interface{})))
	}
	if NotZeroString(data, "policy_uri") {
		newServiceDto.SetPolicyUri(data.Get("policy_uri").(string))
	}
	if NotZeroString(data, "tos_uri") {
		newServiceDto.SetTosUri(data.Get("tos_uri").(string))
	}
	if NotZeroString(data, "service_documentation") {
		newServiceDto.SetServiceDocumentation(data.Get("service_documentation").(string))
	}
	if NotZeroString(data, "backchannel_authentication_endpoint") {
		newServiceDto.SetBackchannelAuthenticationEndpoint(data.Get("backchannel_authentication_endpoint").(string))
	}
	if NotZeroArray(data, "supported_backchannel_token_delivery_modes") {
		newServiceDto.SetSupportedBackchannelTokenDeliveryModes(mapBackchannelDelivery(data.Get("supported_backchannel_token_delivery_modes").([]interface{})))
	}
	if NotZeroNumber(data, "backchannel_auth_req_id_duration") {
		newServiceDto.SetBackchannelAuthReqIdDuration(int32(data.Get("backchannel_auth_req_id_duration").(int)))
	}
	if NotZeroNumber(data, "backcannel_polling_interval") {
		newServiceDto.SetBackchannelPollingInterval(int32(data.Get("backcannel_polling_interval").(int)))
	}
	newServiceDto.SetBackchannelUserCodeParameterSupported(data.Get("backchannel_user_code_parameter_supported").(bool))
	newServiceDto.SetBackchannelBindingMessageRequiredInFapi(data.Get("backchannel_binding_message_required_in_fapi").(bool))
	if NotZeroString(data, "device_authorization_endpoint") {
		newServiceDto.SetDeviceAuthorizationEndpoint(data.Get("device_authorization_endpoint").(string))
	}
	if NotZeroString(data, "device_verification_uri") {
		newServiceDto.SetDeviceVerificationUri(data.Get("device_verification_uri").(string))
	}
	if NotZeroString(data, "device_verification_uri_complete") {
		newServiceDto.SetDeviceVerificationUriComplete(data.Get("device_verification_uri_complete").(string))
	}
	if NotZeroNumber(data, "device_flow_code_duration") {
		newServiceDto.SetDeviceFlowCodeDuration(int32(data.Get("device_flow_code_duration").(int)))
	}
	if NotZeroNumber(data, "device_flow_polling_interval") {
		newServiceDto.SetDeviceFlowPollingInterval(int32(data.Get("device_flow_polling_interval").(int)))
	}
	if NotZeroString(data, "user_code_charset") {
		newServiceDto.SetUserCodeCharset(mapUserCodeCharsets(data.Get("user_code_charset").(string)))
	}
	if NotZeroNumber(data, "user_code_length") {
		newServiceDto.SetUserCodeLength(int32(data.Get("user_code_length").(int)))
	}
	/*
		newServiceDto.SetSupportedTrustFrameworks(mapSetToString(data.Get("supported_trust_frameworks").([]interface{})))
		newServiceDto.SetSupportedEvidence(mapSetToString(data.Get("supported_evidence").([]interface{})))
		newServiceDto.SetSupportedIdentityDocuments(mapSetToString(data.Get("supported_identity_documents").([]interface{})))
		newServiceDto.SetSupportedVerificationMethods(mapSetToString(data.Get("supported_verification_methods").([]interface{})))
		newServiceDto.SetSupportedVerifiedClaims(mapSetToString(data.Get("supported_verified_claims").([]interface{})))
		newServiceDto.SetEndSessionEndpoint(data.Get("end_session_endpoint").(string))
	*/
	return &newServiceDto, diags

}

func serviceToResource(dto *authlete.Service, data *schema.ResourceData) diag.Diagnostics {

	data.SetId(strconv.FormatInt(dto.GetApiKey(), 10))
	data.Set("api_secret", dto.GetApiSecret())
	data.Set("service_name", dto.GetServiceName())
	data.Set("issuer", dto.GetIssuer())
	data.Set("description", dto.GetDescription())
	data.Set("clients_per_developer", dto.GetClientsPerDeveloper())
	data.Set("client_id_alias_enabled", dto.GetClientIdAliasEnabled())

	data.Set("attribute", mapAttributesFromDTO(dto.GetAttributes()))
	data.Set("supported_custom_client_metadata", mapSchemaFromString(dto.GetSupportedCustomClientMetadata()))
	data.Set("authentication_callback_endpoint", dto.GetAuthenticationCallbackEndpoint())
	data.Set("authentication_callback_api_key", dto.GetAuthenticationCallbackApiKey())
	data.Set("authentication_callback_api_secret", dto.GetAuthenticationCallbackApiSecret())
	data.Set("supported_acrs", mapSchemaFromString(dto.GetSupportedAcrs()))
	data.Set("developer_authentication_callback_endpoint", dto.GetDeveloperAuthenticationCallbackEndpoint())
	data.Set("developer_authentication_callback_api_key", dto.GetDeveloperAuthenticationCallbackApiKey())
	data.Set("developer_authentication_callback_api_secret", dto.GetDeveloperAuthenticationCallbackApiSecret())
	data.Set("supported_grant_types", mapGrantTypesFromDTO(dto.GetSupportedGrantTypes()))
	data.Set("supported_response_types", mapResponseTypesFromDTO(dto.GetSupportedResponseTypes()))
	data.Set("supported_authorization_detail_types", mapSchemaFromString(dto.GetSupportedAuthorizationDetailsTypes()))
	data.Set("supported_service_profiles", mapSupportedFrameworkFromDTO(dto.GetSupportedServiceProfiles()))

	data.Set("error_description_omitted", dto.GetErrorDescriptionOmitted())
	data.Set("error_uri_omitted", dto.GetErrorUriOmitted())
	data.Set("authorization_endpoint", dto.GetAuthorizationEndpoint())
	data.Set("direct_authorization_endpoint_enabled", dto.GetDirectAuthorizationEndpointEnabled())
	data.Set("supported_ui_locales", mapSchemaFromString(dto.GetSupportedUiLocales()))
	data.Set("supported_displays", mapSupportedDisplayFromDTO(dto.GetSupportedDisplays()))
	data.Set("pkce_required", dto.GetPkceRequired())
	data.Set("pkce_s256_required", dto.GetPkceS256Required())
	data.Set("authorization_response_duration", dto.GetAuthorizationResponseDuration())
	data.Set("iss_response_suppressed", dto.GetIssSuppressed())
	// data.Set("ignore_port_loopback_redirect", dto.GetLoopbackRedirectionUriVariable())
	data.Set("token_endpoint", dto.GetTokenEndpoint())
	data.Set("direct_token_endpoint_enabled", dto.GetDirectTokenEndpointEnabled())
	data.Set("supported_token_auth_methods", mapClientAuthMethodsFromDTO(dto.GetSupportedTokenAuthMethods()))
	data.Set("mutual_tls_validate_pki_cert_chain", dto.GetMutualTlsValidatePkiCertChain())
	data.Set("trusted_root_certificates", mapSchemaFromString(dto.GetTrustedRootCertificates()))
	data.Set("missing_client_id_allowed", dto.GetMissingClientIdAllowed())
	data.Set("revocation_endpoint", dto.GetRevocationEndpoint())
	data.Set("direct_revocation_endpoint_enabled", dto.GetDirectRevocationEndpointEnabled())
	data.Set("supported_revocation_auth_methods", mapClientAuthMethodsFromDTO(dto.GetSupportedRevocationAuthMethods()))
	data.Set("introspection_endpoint", dto.GetIntrospectionEndpoint())
	data.Set("direct_introspection_endpoint_enabled", dto.GetDirectIntrospectionEndpointEnabled())
	data.Set("supported_introspection_auth_methods", mapClientAuthMethodsFromDTO(dto.GetSupportedIntrospectionAuthMethods()))
	data.Set("pushed_auth_req_endpoint", dto.GetPushedAuthReqEndpoint())
	data.Set("pushed_auth_req_duration", dto.GetPushedAuthReqDuration())
	data.Set("par_required", dto.GetParRequired())
	data.Set("request_object_required", dto.GetRequestObjectRequired())
	data.Set("traditional_request_object_processing_applied", dto.GetTraditionalRequestObjectProcessingApplied())
	data.Set("nbf_optional", dto.GetNbfOptional())
	data.Set("front_channel_encryption_request_obj_required", dto.GetFrontChannelRequestObjectEncryptionRequired())
	data.Set("encryption_alg_req_obj_match", dto.GetRequestObjectEncryptionAlgMatchRequired())
	data.Set("encryption_enc_alg_req_obj_match", dto.GetRequestObjectEncryptionEncMatchRequired())
	data.Set("access_token_type", dto.GetAccessTokenType())
	data.Set("tls_client_certificate_bound_access_tokens", dto.GetTlsClientCertificateBoundAccessTokens())
	data.Set("access_token_duration", dto.GetAccessTokenDuration())
	data.Set("single_access_token_per_subject", dto.GetSingleAccessTokenPerSubject())
	data.Set("access_token_sign_alg", dto.GetAccessTokenSignAlg())
	data.Set("access_token_signature_key_id", dto.GetAccessTokenSignatureKeyId())
	data.Set("refresh_token_duration", dto.GetRefreshTokenDuration())
	data.Set("refresh_token_duration_kept", dto.GetRefreshTokenDurationKept())
	data.Set("refresh_token_duration_reset", dto.GetRefreshTokenDurationReset())
	data.Set("refresh_token_kept", dto.GetRefreshTokenKept())
	data.Set("token_expiration_link", dto.GetTokenExpirationLinked())
	data.Set("supported_scopes", mapSupportedScopeFromDTO(dto.GetSupportedScopes()))
	data.Set("scope_required", dto.GetScopeRequired())
	data.Set("id_token_duration", dto.GetIdTokenDuration())
	data.Set("allowable_clock_skew", dto.GetAllowableClockSkew())
	data.Set("supported_claim_types", mapClaimTypesFromDTO(dto.GetSupportedClaimTypes()))
	data.Set("supported_claim_locales", mapSchemaFromString(dto.GetSupportedClaimLocales()))
	data.Set("supported_claims", mapSchemaFromString(dto.GetSupportedClaims()))
	data.Set("claim_shortcut_restrictive", dto.GetClaimShortcutRestrictive())
	data.Set("jwks_endpoint", dto.GetJwksUri())
	data.Set("direct_jwks_endpoint_enabled", dto.GetDirectJwksEndpointEnabled())
	jwk, err := mapJWKFromDTO(data.Get("jwk").([]interface{}), dto.GetJwks())
	if err != nil {
		return diag.FromErr(err)
	}
	data.Set("jwk", jwk)
	data.Set("id_token_signature_key_id", dto.GetIdTokenSignatureKeyId())
	data.Set("user_info_signature_key_id", dto.GetUserInfoSignatureKeyId())
	data.Set("authorization_signature_key_id", dto.GetAuthorizationSignatureKeyId())
	data.Set("hsm_enabled", dto.GetHsmEnabled())
	data.Set("user_info_endpoint", dto.GetUserInfoEndpoint())
	data.Set("direct_user_info_endpoint_enabled", dto.GetDirectUserInfoEndpointEnabled())
	data.Set("dynamic_registration_supported", dto.GetDynamicRegistrationSupported())
	// data.Set("dcr_scope_used_as_requestable", dto.GetDcrScopeUsedAsRequestable())
	data.Set("registration_endpoint", dto.GetRegistrationEndpoint())
	data.Set("registration_management_endpoint", dto.GetRegistrationManagementEndpoint())
	data.Set("mtls_endpoint_aliases", mapMtlsEndpointFromDTO(dto.GetMtlsEndpointAliases()))
	data.Set("policy_uri", dto.GetPolicyUri())
	data.Set("tos_uri", dto.GetTosUri())
	data.Set("service_documentation", dto.GetServiceDocumentation())
	data.Set("backchannel_authentication_endpoint", dto.GetBackchannelAuthenticationEndpoint())
	data.Set("supported_backchannel_token_delivery_modes", mapBackchannelDeliveryFromDTO(dto.GetSupportedBackchannelTokenDeliveryModes()))
	data.Set("backchannel_auth_req_id_duration", dto.GetBackchannelAuthReqIdDuration())
	data.Set("backcannel_polling_interval", dto.GetBackchannelPollingInterval())
	data.Set("backchannel_user_code_parameter_supported", dto.GetBackchannelUserCodeParameterSupported())
	data.Set("backchannel_binding_message_required_in_fapi", dto.GetBackchannelBindingMessageRequiredInFapi())
	data.Set("device_authorization_endpoint", dto.GetDeviceAuthorizationEndpoint())
	data.Set("device_verification_uri", dto.GetDeviceVerificationUri())
	data.Set("device_verification_uri_complete", dto.GetDeviceVerificationUriComplete())
	data.Set("device_flow_code_duration", dto.GetDeviceFlowCodeDuration())
	data.Set("device_flow_polling_interval", dto.GetDeviceFlowPollingInterval())
	data.Set("user_code_charset", mapUserCodeCharsetsFromDTO(dto.GetUserCodeCharset()))
	data.Set("user_code_length", dto.GetUserCodeLength())

	/*
		data.Set("supported_trust_frameworks", mapSchemaFromString(&dto.GetSupportedTrustFrameworks()))
		data.Set("supported_evidence", mapSchemaFromString(&dto.GetSupportedEvidence()))
		data.Set("supported_identity_documents", mapSchemaFromString(&dto.GetSupportedIdentityDocuments()))
		data.Set("supported_verification_methods", mapSchemaFromString(&dto.GetSupportedVerificationMethods))
		data.Set("supported_verified_claims", mapSchemaFromString(&dto.GetSupportedVerifiedClaims))
	*/
	data.Set("end_session_endpoint", dto.GetEndSessionEndpoint)
	return nil
}

func mapSetToString(vals []interface{}) []string {
	values := make([]string, len(vals))

	for i, v := range vals {
		values[i] = v.(string)
	}

	return values
}

func mapSchemaFromString(vals []string) []interface{} {
	if vals != nil {
		entries := make([]interface{}, len(vals), len(vals))
		for i, v := range vals {
			entries[i] = v
		}
		return entries
	}
	return make([]interface{}, 0)
}

func createStringColSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
	}
}

func difference(a, b []interface{}) []interface{} {
	mb := make(map[interface{}]interface{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []interface{}
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}
