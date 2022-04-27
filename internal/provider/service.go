package provider

import (
	"context"
	"strconv"

	"github.com/authlete/authlete-go/dto"

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

	newService, err := client.authleteClient.CreateService(newServiceDto)

	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Service created")

	api_key := newService.ApiKey
	api_secret := newService.ApiSecret

	// populate the state with default values coming from authlete api server.
	diags = serviceToResource(newService, d)

	d.SetId(strconv.FormatUint(api_key, 10))
	d.Set("api_secret", api_secret)

	return diags

}

func serviceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	return serviceReadInternal(ctx, d, meta, diags)
}

func serviceReadInternal(ctx context.Context, d *schema.ResourceData, meta interface{}, diags diag.Diagnostics) diag.Diagnostics {
	client := meta.(*apiClient)

	dto, err := client.authleteClient.GetService(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	diags = serviceToResource(dto, d)

	return diags
}

func serviceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics

	client := meta.(*apiClient)

	srv, err := client.authleteClient.GetService(d.Id())

	if err != nil {
		return diag.FromErr(err)
	}

	if d.HasChange("service_name") {
		srv.ServiceName = d.Get("service_name").(string)
	}
	if d.HasChange("issuer") {
		srv.Issuer = d.Get("issuer").(string)
	}
	if d.HasChange("description") {
		srv.Description = d.Get("description").(string)
	}
	if d.HasChange("clients_per_developer") {
		srv.ClientsPerDeveloper = d.Get("clients_per_developer").(uint16)
	}
	if d.HasChange("client_id_alias_enabled") {
		srv.ClientIdAliaseEnabled = d.Get("client_id_alias_enabled").(bool)
	}
	if d.HasChange("attributes") {
		srv.Attributes = mapAttributesToDTO(d.Get("attribute").([]interface{}))
	}
	if d.HasChange("supported_custom_client_metadata") {
		srv.SupportedCustomClientMetadata = mapSetToString(d.Get("supported_custom_client_metadata").([]interface{}))
	}
	if d.HasChange("authentication_callback_endpoint") {
		srv.AuthenticationCallbackEndpoint = d.Get("authentication_callback_endpoint").(string)
	}
	if d.HasChange("authentication_callback_api_key") {
		srv.AuthenticationCallbackApiKey = d.Get("authentication_callback_api_key").(string)
	}
	if d.HasChange("authentication_callback_api_secret") {
		srv.AuthenticationCallbackApiSecret = d.Get("authentication_callback_api_secret").(string)
	}
	if d.HasChange("supported_acrs") {
		srv.SupportedAcrs = mapSetToString(d.Get("supported_acrs").([]interface{}))
	}
	if d.HasChange("developer_authentication_callback_endpoint") {
		srv.DeveloperAuthenticationCallbackEndpoint = d.Get("developer_authentication_callback_endpoint").(string)
	}
	if d.HasChange("developer_authentication_callback_api_key") {
		srv.DeveloperAuthenticationCallbackApiKey = d.Get("developer_authentication_callback_api_key").(string)
	}
	if d.HasChange("developer_authentication_callback_api_secret") {
		srv.DeveloperAuthenticationCallbackApiSecret = d.Get("developer_authentication_callback_api_secret").(string)
	}

	if d.HasChange("supported_grant_types") {
		srv.SupportedGrantTypes = mapGrantTypesToDTO(d.Get("supported_grant_types").([]interface{}))
	}
	if d.HasChange("supported_response_types") {
		srv.SupportedResponseTypes = mapResponseTypesToDTO(d.Get("supported_response_types").([]interface{}))
	}
	if d.HasChange("supported_authorization_detail_types") {
		srv.SupportedAuthorizationDetailsTypes = mapSetToString(d.Get("supported_authorization_detail_types").([]interface{}))
	}
	if d.HasChange("supported_service_profiles") {
		srv.SupportedServiceProfiles = mapSupportedFrameworkToDTO(d.Get("supported_service_profiles").([]interface{}))
	}
	if d.HasChange("error_description_omitted") {
		srv.ErrorDescriptionOmitted = d.Get("error_description_omitted").(bool)
	}
	if d.HasChange("error_uri_omitted") {
		srv.ErrorUriOmitted = d.Get("error_uri_omitted").(bool)
	}
	if d.HasChange("authorization_endpoint") {
		srv.AuthorizationEndpoint = d.Get("authorization_endpoint").(string)
	}
	if d.HasChange("direct_authorization_endpoint_enabled") {
		srv.DirectAuthorizationEndpointEnabled = d.Get("direct_authorization_endpoint_enabled").(bool)
	}
	if d.HasChange("supported_ui_locales") {
		srv.SupportedUiLocales = mapSetToString(d.Get("supported_ui_locales").([]interface{}))
	}
	if d.HasChange("supported_displays") {
		srv.SupportedDisplays = mapSupportedDisplay(d.Get("supported_displays").([]interface{}))
	}
	if d.HasChange("pkce_required") {
		srv.PkceRequired = d.Get("pkce_required").(bool)
	}
	if d.HasChange("pkce_s256_required") {
		srv.PkceS256Required = d.Get("pkce_s256_required").(bool)
	}
	if d.HasChange("authorization_response_duration") {
		srv.AuthorizationResponseDuration = uint64(d.Get("authorization_response_duration").(int))
	}
	if d.HasChange("iss_response_parameter") {
		srv.IssSuppressed = d.Get("iss_response_suppressed").(bool)
	}
	// if d.HasChange("ignore_port_loopback_redirect") {
	//	srv.LoopbackRedirectionUriVariable = d.Get("ignore_port_loopback_redirect").(bool)
	// }
	if d.HasChange("token_endpoint") {
		srv.TokenEndpoint = d.Get("token_endpoint").(string)
	}
	if d.HasChange("direct_token_endpoint_enabled") {
		srv.DirectTokenEndpointEnabled = d.Get("direct_token_endpoint_enabled").(bool)
	}
	if d.HasChange("supported_token_auth_methods") {
		srv.SupportedTokenAuthMethods = mapClientAuthMethods(d.Get("supported_token_auth_methods").([]interface{}))
	}
	if d.HasChange("mutual_tls_validate_pki_cert_chain") {
		srv.MutualTlsValidatePkiCertChain = d.Get("mutual_tls_validate_pki_cert_chain").(bool)
	}
	if d.HasChange("trusted_root_certificates") {
		srv.TrustedRootCertificates = mapSetToString(d.Get("trusted_root_certificates").([]interface{}))
	}
	if d.HasChange("missing_client_id_allowed") {
		srv.MissingClientIdAllowed = d.Get("missing_client_id_allowed").(bool)
	}
	if d.HasChange("revocation_endpoint") {
		srv.RevocationEndpoint = d.Get("revocation_endpoint").(string)
	}
	if d.HasChange("direct_revocation_endpoint_enabled") {
		srv.DirectRevocationEndpointEnabled = d.Get("direct_revocation_endpoint_enabled").(bool)
	}
	if d.HasChange("supported_revocation_auth_methods") {
		srv.SupportedRevocationAuthMethods = mapClientAuthMethods(d.Get("supported_revocation_auth_methods").([]interface{}))
	}
	if d.HasChange("introspection_endpoint") {
		srv.IntrospectionEndpoint = d.Get("introspection_endpoint").(string)
	}
	if d.HasChange("direct_introspection_endpoint_enabled") {
		srv.DirectIntrospectionEndpointEnabled = d.Get("direct_introspection_endpoint_enabled").(bool)
	}
	if d.HasChange("supported_introspection_auth_methods") {
		srv.SupportedIntrospectionAuthMethods = mapClientAuthMethods(d.Get("supported_introspection_auth_methods").([]interface{}))
	}
	if d.HasChange("pushed_auth_req_endpoint") {
		srv.PushedAuthReqEndpoint = d.Get("pushed_auth_req_endpoint").(string)
	}
	if d.HasChange("pushed_auth_req_duration") {
		srv.PushedAuthReqDuration = uint64(d.Get("pushed_auth_req_duration").(int))
	}
	if d.HasChange("par_required") {
		srv.ParRequired = d.Get("par_required").(bool)
	}
	if d.HasChange("request_object_required") {
		srv.RequestObjectRequired = d.Get("request_object_required").(bool)
	}
	if d.HasChange("traditional_request_object_processing_applied") {
		srv.TraditionalRequestObjectProcessingApplied = d.Get("traditional_request_object_processing_applied").(bool)
	}
	if d.HasChange("nbf_optional") {
		srv.NbfOptional = d.Get("nbf_optional").(bool)
	}
	if d.HasChange("front_channel_encryption_request_obj_required") {
		srv.FrontChannelRequestObjectEncryptionRequired = d.Get("front_channel_encryption_request_obj_required").(bool)
	}
	if d.HasChange("encryption_alg_req_obj_match") {
		srv.RequestObjectEncryptionAlgMatchRequired = d.Get("encryption_alg_req_obj_match").(bool)
	}
	if d.HasChange("encryption_enc_alg_req_obj_match") {
		srv.RequestObjectEncryptionEncMatchRequired = d.Get("encryption_enc_alg_req_obj_match").(bool)
	}
	if d.HasChange("access_token_type") {
		srv.AccessTokenType = d.Get("access_token_type").(string)
	}
	if d.HasChange("single_access_token_per_subject") {
		srv.SingleAccessTokenPerSubject = d.Get("single_access_token_per_subject").(bool)
	}

	if d.HasChange("access_token_sign_alg") {
		srv.AccessTokenSignAlg = mapSignAlgorithms(d.Get("access_token_sign_alg").(string))
	}
	if d.HasChange("access_token_signature_key_id") {
		srv.AccessTokenSignatureKeyId = d.Get("access_token_signature_key_id").(string)
	}
	if d.HasChange("refresh_token_duration") {
		srv.RefreshTokenDuration = uint64(d.Get("refresh_token_duration").(int))
	}
	if d.HasChange("refresh_token_duration_kept") {
		srv.RefreshTokenDurationKept = d.Get("refresh_token_duration_kept").(bool)
	}
	if d.HasChange("refresh_token_duration_reset") {
		srv.RefreshTokenDurationReset = d.Get("refresh_token_duration_reset").(bool)
	}
	if d.HasChange("refresh_token_kept") {
		srv.RefreshTokenKept = d.Get("refresh_token_kept").(bool)
	}
	if d.HasChange("token_expiration_link") {
		srv.TokenExpirationLinked = d.Get("token_expiration_link").(bool)
	}
	if d.HasChange("supported_scopes") {
		srv.SupportedScopes = mapSupportedScope(d.Get("supported_scopes").([]interface{}))
	}
	if d.HasChange("scope_required") {
		srv.ScopeRequired = d.Get("scope_required").(bool)
	}
	if d.HasChange("id_token_duration") {
		srv.IdTokenDuration = uint64(d.Get("id_token_duration").(int))
	}
	if d.HasChange("allowable_clock_skew") {
		srv.AllowableClockSkew = uint16(d.Get("allowable_clock_skew").(int))
	}
	if d.HasChange("supported_claim_types") {
		srv.SupportedClaimTypes = mapClaimTypes(d.Get("supported_claim_types").([]interface{}))
	}
	if d.HasChange("supported_claim_locales") {
		srv.SupportedClaimLocales = mapSetToString(d.Get("supported_claim_locales").([]interface{}))
	}
	if d.HasChange("supported_claims") {
		srv.SupportedClaims = mapSetToString(d.Get("supported_claims").([]interface{}))
	}
	if d.HasChange("claim_shortcut_restrictive") {
		srv.ClaimShortcutRestrictive = d.Get("claim_shortcut_restrictive").(bool)
	}
	if d.HasChange("jwks_endpoint") {
		srv.JwksUri = d.Get("jwks_endpoint").(string)
	}
	if d.HasChange("direct_jwks_endpoint_enabled") {
		srv.DirectJwksEndpointEnabled = d.Get("direct_jwks_endpoint_enabled").(bool)
	}
	if d.HasChange("jwk") {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Updating Description",
			Detail:   "Updating Description name to " + d.Get("description").(string),
		})

		srv.Jwks, diags = updateJWKS(d.Get("jwk").([]interface{}), srv.Jwks, diags)
	}

	if d.HasChange("id_token_signature_key_id") {
		srv.IdTokenSignatureKeyId = d.Get("id_token_signature_key_id").(string)
	}
	if d.HasChange("user_info_signature_key_id") {
		srv.UserInfoSignatureKeyId = d.Get("user_info_signature_key_id").(string)
	}
	if d.HasChange("authorization_signature_key_id") {
		srv.AuthorizationSignatureKeyId = d.Get("authorization_signature_key_id").(string)
	}
	if d.HasChange("hsm_enabled") {
		srv.HsmEnabled = d.Get("hsm_enabled").(bool)
	}
	if d.HasChange("user_info_endpoint") {
		srv.UserInfoEndpoint = d.Get("user_info_endpoint").(string)
	}
	if d.HasChange("direct_user_info_endpoint_enabled") {
		srv.DirectUserInfoEndpointEnabled = d.Get("direct_user_info_endpoint_enabled").(bool)
	}
	if d.HasChange("dynamic_registration_supported") {
		srv.DynamicRegistrationSupported = d.Get("dynamic_registration_supported").(bool)
	}
	// if d.HasChange("dcr_scope_used_as_requestable") {
	//	srv.DcrScopeUsedAsRequestable = d.Get("dcr_scope_used_as_requestable").(bool)
	// }
	if d.HasChange("registration_endpoint") {
		srv.RegistrationEndpoint = d.Get("registration_endpoint").(string)
	}
	if d.HasChange("registration_management_endpoint") {
		srv.RegistrationManagementEndpoint = d.Get("registration_management_endpoint").(string)
	}
	if d.HasChange("mtls_endpoint_aliases") {
		srv.MtlsEndpointAliases = mapMtlsEndpoint(d.Get("mtls_endpoint_aliases").([]interface{}))
	}
	if d.HasChange("policy_uri") {
		srv.PolicyUri = d.Get("policy_uri").(string)
	}
	if d.HasChange("tos_uri") {
		srv.TosUri = d.Get("tos_uri").(string)
	}
	if d.HasChange("service_documentation") {
		srv.ServiceDocumentation = d.Get("service_documentation").(string)
	}
	if d.HasChange("backchannel_authentication_endpoint") {
		srv.BackchannelAuthenticationEndpoint = d.Get("backchannel_authentication_endpoint").(string)
	}
	if d.HasChange("supported_backchannel_token_delivery_modes") {
		srv.SupportedBackchannelTokenDeliveryModes = mapBackchannelDelivery(d.Get("supported_backchannel_token_delivery_modes").([]interface{}))
	}
	if d.HasChange("backchannel_auth_req_id_duration") {
		srv.BackchannelAuthReqIdDuration = uint64(d.Get("backchannel_auth_req_id_duration").(int))
	}
	if d.HasChange("backcannel_polling_interval") {
		srv.BachcannelPollingInterval = uint16(d.Get("backcannel_polling_interval").(int))
	}
	if d.HasChange("backchannel_user_code_parameter_supported") {
		srv.BackchannelUserCodeParameterSupported = d.Get("backchannel_user_code_parameter_supported").(bool)
	}
	if d.HasChange("backchannel_binding_message_required_in_fapi") {
		srv.BackchannelBindingMessageRequiredInFapi = d.Get("backchannel_binding_message_required_in_fapi").(bool)
	}
	if d.HasChange("device_authorization_endpoint") {
		srv.DeviceAuthorizationEndpoint = d.Get("device_authorization_endpoint").(string)
	}
	if d.HasChange("device_verification_uri") {
		srv.DeviceVerificationUri = d.Get("device_verification_uri").(string)
	}
	if d.HasChange("device_verification_uri_complete") {
		srv.DeviceVerificationUriComplete = d.Get("device_verification_uri_complete").(string)
	}
	if d.HasChange("device_flow_code_duration") {
		srv.DeviceFlowCodeDuration = uint64(d.Get("device_flow_code_duration").(int))
	}
	if d.HasChange("device_flow_polling_interval") {
		srv.DeviceFlowPollingInterval = uint16(d.Get("device_flow_polling_interval").(int))
	}
	if d.HasChange("user_code_charset") {
		srv.UserCodeCharset = mapUserCodeCharsets(d.Get("user_code_charset").(string))
	}
	if d.HasChange("user_code_length") {
		srv.UserCodeLength = uint8(d.Get("user_code_length").(int))
	}
	/*
		if d.HasChange("supported_trust_frameworks") {
			srv.SupportedTrustFrameworks = mapSetToString(d.Get("supported_trust_frameworks").(*schema.Set))
		}
		if d.HasChange("supported_evidence") {
			srv.SupportedEvidence = mapSetToString(d.Get("supported_evidence").(*schema.Set))
		}
		if d.HasChange("supported_identity_documents") {
			srv.SupportedIdentityDocuments = mapSetToString(d.Get("supported_identity_documents").(*schema.Set))
		}
		if d.HasChange("supported_verification_methods") {
			srv.SupportedVerificationMethods = mapSetToString(d.Get("supported_verification_methods").(*schema.Set))
		}
		if d.HasChange("supported_verified_claims") {
			srv.SupportedVerifiedClaims = mapSetToString(d.Get("supported_verified_claims").(*schema.Set))
		}
	*/
	if d.HasChange("end_session_endpoint") {
		srv.EndSessionEndpoint = d.Get("end_session_endpoint").(string)
	}

	_, err = client.authleteClient.UpdateService(srv)

	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func serviceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	// client := meta.(*apiClient)

	client := meta.(*apiClient)

	err := client.authleteClient.DeleteService(d.Id())

	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func dataToService(data *schema.ResourceData, diags diag.Diagnostics) (*dto.Service, diag.Diagnostics) {

	newServiceDto := dto.Service{}

	newServiceDto.ServiceName = data.Get("service_name").(string)
	newServiceDto.Issuer = data.Get("issuer").(string)
	newServiceDto.Description = data.Get("description").(string)
	newServiceDto.ClientsPerDeveloper = uint16(data.Get("clients_per_developer").(int))
	newServiceDto.ClientIdAliaseEnabled = data.Get("client_id_alias_enabled").(bool)
	newServiceDto.Attributes = mapAttributesToDTO(data.Get("attribute").([]interface{}))
	newServiceDto.SupportedCustomClientMetadata = mapSetToString(data.Get("supported_custom_client_metadata").([]interface{}))
	newServiceDto.AuthenticationCallbackEndpoint = data.Get("authentication_callback_endpoint").(string)
	newServiceDto.AuthenticationCallbackApiKey = data.Get("authentication_callback_api_key").(string)
	newServiceDto.AuthenticationCallbackApiSecret = data.Get("authentication_callback_api_secret").(string)
	newServiceDto.SupportedAcrs = mapSetToString(data.Get("supported_acrs").([]interface{}))
	newServiceDto.DeveloperAuthenticationCallbackEndpoint = data.Get("developer_authentication_callback_endpoint").(string)
	newServiceDto.DeveloperAuthenticationCallbackApiKey = data.Get("developer_authentication_callback_api_key").(string)
	newServiceDto.DeveloperAuthenticationCallbackApiSecret = data.Get("developer_authentication_callback_api_secret").(string)
	newServiceDto.SupportedGrantTypes = mapGrantTypesToDTO(data.Get("supported_grant_types").([]interface{}))
	newServiceDto.SupportedResponseTypes = mapResponseTypesToDTO(data.Get("supported_response_types").([]interface{}))
	newServiceDto.SupportedAuthorizationDetailsTypes = mapSetToString(data.Get("supported_authorization_detail_types").([]interface{}))
	newServiceDto.SupportedServiceProfiles = mapSupportedFrameworkToDTO(data.Get("supported_service_profiles").([]interface{}))
	newServiceDto.ErrorDescriptionOmitted = data.Get("error_description_omitted").(bool)
	newServiceDto.ErrorUriOmitted = data.Get("error_uri_omitted").(bool)
	newServiceDto.AuthorizationEndpoint = data.Get("authorization_endpoint").(string)
	newServiceDto.DirectAuthorizationEndpointEnabled = data.Get("direct_authorization_endpoint_enabled").(bool)
	newServiceDto.SupportedUiLocales = mapSetToString(data.Get("supported_ui_locales").([]interface{}))
	newServiceDto.SupportedDisplays = mapSupportedDisplay(data.Get("supported_displays").([]interface{}))
	newServiceDto.PkceRequired = data.Get("pkce_required").(bool)
	newServiceDto.PkceS256Required = data.Get("pkce_s256_required").(bool)
	newServiceDto.AuthorizationResponseDuration = uint64(data.Get("authorization_response_duration").(int))
	newServiceDto.IssSuppressed = data.Get("iss_response_suppressed").(bool)
	// newServiceDto.LoopbackRedirectionUriVariable = data.Get("ignore_port_loopback_redirect").(bool)
	newServiceDto.TokenEndpoint = data.Get("token_endpoint").(string)
	newServiceDto.DirectTokenEndpointEnabled = data.Get("direct_token_endpoint_enabled").(bool)
	newServiceDto.SupportedTokenAuthMethods = mapClientAuthMethods(data.Get("supported_token_auth_methods").([]interface{}))
	newServiceDto.MutualTlsValidatePkiCertChain = data.Get("mutual_tls_validate_pki_cert_chain").(bool)
	newServiceDto.TrustedRootCertificates = mapSetToString(data.Get("trusted_root_certificates").([]interface{}))
	newServiceDto.MissingClientIdAllowed = data.Get("missing_client_id_allowed").(bool)
	newServiceDto.RevocationEndpoint = data.Get("revocation_endpoint").(string)
	newServiceDto.DirectRevocationEndpointEnabled = data.Get("direct_revocation_endpoint_enabled").(bool)
	newServiceDto.SupportedRevocationAuthMethods = mapClientAuthMethods(data.Get("supported_revocation_auth_methods").([]interface{}))
	newServiceDto.IntrospectionEndpoint = data.Get("introspection_endpoint").(string)
	newServiceDto.DirectIntrospectionEndpointEnabled = data.Get("direct_introspection_endpoint_enabled").(bool)
	newServiceDto.SupportedIntrospectionAuthMethods = mapClientAuthMethods(data.Get("supported_introspection_auth_methods").([]interface{}))
	newServiceDto.PushedAuthReqEndpoint = data.Get("pushed_auth_req_endpoint").(string)
	newServiceDto.PushedAuthReqDuration = uint64(data.Get("pushed_auth_req_duration").(int))
	newServiceDto.ParRequired = data.Get("par_required").(bool)
	newServiceDto.RequestObjectRequired = data.Get("request_object_required").(bool)
	newServiceDto.TraditionalRequestObjectProcessingApplied = data.Get("traditional_request_object_processing_applied").(bool)
	newServiceDto.NbfOptional = data.Get("nbf_optional").(bool)
	newServiceDto.FrontChannelRequestObjectEncryptionRequired = data.Get("front_channel_encryption_request_obj_required").(bool)
	newServiceDto.RequestObjectEncryptionAlgMatchRequired = data.Get("encryption_alg_req_obj_match").(bool)
	newServiceDto.RequestObjectEncryptionEncMatchRequired = data.Get("encryption_enc_alg_req_obj_match").(bool)
	newServiceDto.AccessTokenType = data.Get("access_token_type").(string)
	newServiceDto.TlsClientCertificateBoundAccessTokens = data.Get("tls_client_certificate_bound_access_tokens").(bool)
	newServiceDto.AccessTokenDuration = uint64(data.Get("access_token_duration").(int))
	newServiceDto.SingleAccessTokenPerSubject = data.Get("single_access_token_per_subject").(bool)
	newServiceDto.AccessTokenSignAlg = mapSignAlgorithms(data.Get("access_token_sign_alg").(string))
	newServiceDto.AccessTokenSignatureKeyId = data.Get("access_token_signature_key_id").(string)
	newServiceDto.RefreshTokenDuration = uint64(data.Get("refresh_token_duration").(int))
	newServiceDto.RefreshTokenDurationKept = data.Get("refresh_token_duration_kept").(bool)
	newServiceDto.RefreshTokenDurationReset = data.Get("refresh_token_duration_reset").(bool)
	newServiceDto.RefreshTokenKept = data.Get("refresh_token_kept").(bool)
	newServiceDto.TokenExpirationLinked = data.Get("token_expiration_link").(bool)
	newServiceDto.SupportedScopes = mapSupportedScope(data.Get("supported_scopes").([]interface{}))
	newServiceDto.ScopeRequired = data.Get("scope_required").(bool)
	newServiceDto.IdTokenDuration = uint64(data.Get("id_token_duration").(int))
	newServiceDto.AllowableClockSkew = uint16(data.Get("allowable_clock_skew").(int))
	newServiceDto.SupportedClaimTypes = mapClaimTypes(data.Get("supported_claim_types").([]interface{}))
	newServiceDto.SupportedClaimLocales = mapSetToString(data.Get("supported_claim_locales").([]interface{}))
	newServiceDto.SupportedClaims = mapSetToString(data.Get("supported_claims").([]interface{}))
	newServiceDto.ClaimShortcutRestrictive = data.Get("claim_shortcut_restrictive").(bool)
	newServiceDto.JwksUri = data.Get("jwks_endpoint").(string)
	newServiceDto.DirectJwksEndpointEnabled = data.Get("direct_jwks_endpoint_enabled").(bool)
	newServiceDto.Jwks, diags = mapJWKS(data.Get("jwk").([]interface{}), diags)
	newServiceDto.IdTokenSignatureKeyId = data.Get("id_token_signature_key_id").(string)
	newServiceDto.UserInfoSignatureKeyId = data.Get("user_info_signature_key_id").(string)
	newServiceDto.AuthorizationSignatureKeyId = data.Get("authorization_signature_key_id").(string)
	newServiceDto.HsmEnabled = data.Get("hsm_enabled").(bool)
	newServiceDto.UserInfoEndpoint = data.Get("user_info_endpoint").(string)
	newServiceDto.DirectUserInfoEndpointEnabled = data.Get("direct_user_info_endpoint_enabled").(bool)
	newServiceDto.DynamicRegistrationSupported = data.Get("dynamic_registration_supported").(bool)
	// newServiceDto.DcrScopeUsedAsRequestable = data.Get("dcr_scope_used_as_requestable").(bool)
	newServiceDto.RegistrationEndpoint = data.Get("registration_endpoint").(string)
	newServiceDto.RegistrationManagementEndpoint = data.Get("registration_management_endpoint").(string)
	newServiceDto.MtlsEndpointAliases = mapMtlsEndpoint(data.Get("mtls_endpoint_aliases").([]interface{}))
	newServiceDto.PolicyUri = data.Get("policy_uri").(string)
	newServiceDto.TosUri = data.Get("tos_uri").(string)
	newServiceDto.ServiceDocumentation = data.Get("service_documentation").(string)
	newServiceDto.BackchannelAuthenticationEndpoint = data.Get("backchannel_authentication_endpoint").(string)
	newServiceDto.SupportedBackchannelTokenDeliveryModes = mapBackchannelDelivery(data.Get("supported_backchannel_token_delivery_modes").([]interface{}))
	newServiceDto.BackchannelAuthReqIdDuration = uint64(data.Get("backchannel_auth_req_id_duration").(int))
	newServiceDto.BachcannelPollingInterval = uint16(data.Get("backcannel_polling_interval").(int))
	newServiceDto.BackchannelUserCodeParameterSupported = data.Get("backchannel_user_code_parameter_supported").(bool)
	newServiceDto.BackchannelBindingMessageRequiredInFapi = data.Get("backchannel_binding_message_required_in_fapi").(bool)
	newServiceDto.DeviceAuthorizationEndpoint = data.Get("device_authorization_endpoint").(string)
	newServiceDto.DeviceVerificationUri = data.Get("device_verification_uri").(string)
	newServiceDto.DeviceVerificationUriComplete = data.Get("device_verification_uri_complete").(string)
	newServiceDto.DeviceFlowCodeDuration = uint64(data.Get("device_flow_code_duration").(int))
	newServiceDto.DeviceFlowPollingInterval = uint16(data.Get("device_flow_polling_interval").(int))
	newServiceDto.UserCodeCharset = mapUserCodeCharsets(data.Get("user_code_charset").(string))
	newServiceDto.UserCodeLength = uint8(data.Get("user_code_length").(int))
	/*
		newServiceDto.SupportedTrustFrameworks = mapSetToString(data.Get("supported_trust_frameworks").(*schema.Set))
		newServiceDto.SupportedEvidence = mapSetToString(data.Get("supported_evidence").(*schema.Set))
		newServiceDto.SupportedIdentityDocuments = mapSetToString(data.Get("supported_identity_documents").(*schema.Set))
		newServiceDto.SupportedVerificationMethods = mapSetToString(data.Get("supported_verification_methods").(*schema.Set))
		newServiceDto.SupportedVerifiedClaims = mapSetToString(data.Get("supported_verified_claims").(*schema.Set))
	*/
	newServiceDto.EndSessionEndpoint = data.Get("end_session_endpoint").(string)

	return &newServiceDto, diags

}

func serviceToResource(dto *dto.Service, data *schema.ResourceData) diag.Diagnostics {

	data.Set("service_name", dto.ServiceName)
	data.Set("issuer", dto.Issuer)
	data.Set("description", dto.Description)
	data.Set("clients_per_developer", dto.ClientsPerDeveloper)
	data.Set("client_id_alias_enabled", dto.ClientIdAliaseEnabled)

	data.Set("attribute", mapAttributesFromDTO(&dto.Attributes))
	data.Set("supported_custom_client_metadata", mapSchemaFromString(&dto.SupportedCustomClientMetadata))
	data.Set("authentication_callback_endpoint", dto.AuthenticationCallbackEndpoint)
	data.Set("authentication_callback_api_key", dto.AuthenticationCallbackApiKey)
	data.Set("authentication_callback_api_secret", dto.AuthenticationCallbackApiSecret)
	data.Set("supported_acrs", mapSchemaFromString(&dto.SupportedAcrs))
	data.Set("developer_authentication_callback_endpoint", dto.DeveloperAuthenticationCallbackEndpoint)
	data.Set("developer_authentication_callback_api_key", dto.DeveloperAuthenticationCallbackApiKey)
	data.Set("developer_authentication_callback_api_secret", dto.DeveloperAuthenticationCallbackApiSecret)
	data.Set("supported_grant_types", mapGrantTypesFromDTO(&dto.SupportedGrantTypes))
	data.Set("supported_response_types", mapResponseTypesFromDTO(&dto.SupportedResponseTypes))
	data.Set("supported_authorization_detail_types", mapSchemaFromString(&dto.SupportedAuthorizationDetailsTypes))
	data.Set("supported_service_profiles", mapSupportedFrameworkFromDTO(&dto.SupportedServiceProfiles))

	data.Set("error_description_omitted", dto.ErrorDescriptionOmitted)
	data.Set("error_uri_omitted", dto.ErrorUriOmitted)
	data.Set("authorization_endpoint", dto.AuthorizationEndpoint)
	data.Set("direct_authorization_endpoint_enabled", dto.DirectAuthorizationEndpointEnabled)
	data.Set("supported_ui_locales", mapSchemaFromString(&dto.SupportedUiLocales))
	data.Set("supported_displays", mapSupportedDisplayFromDTO(&dto.SupportedDisplays))
	data.Set("pkce_required", dto.PkceRequired)
	data.Set("pkce_s256_required", dto.PkceS256Required)
	data.Set("authorization_response_duration", dto.AuthorizationResponseDuration)
	data.Set("iss_response_suppressed", dto.IssSuppressed)
	// data.Set("ignore_port_loopback_redirect", dto.LoopbackRedirectionUriVariable)
	data.Set("token_endpoint", dto.TokenEndpoint)
	data.Set("direct_token_endpoint_enabled", dto.DirectTokenEndpointEnabled)
	data.Set("supported_token_auth_methods", mapClientAuthMethodsFromDTO(&dto.SupportedTokenAuthMethods))
	data.Set("mutual_tls_validate_pki_cert_chain", dto.MutualTlsValidatePkiCertChain)
	data.Set("trusted_root_certificates", mapSchemaFromString(&dto.TrustedRootCertificates))
	data.Set("missing_client_id_allowed", dto.MissingClientIdAllowed)
	data.Set("revocation_endpoint", dto.RevocationEndpoint)
	data.Set("direct_revocation_endpoint_enabled", dto.DirectRevocationEndpointEnabled)
	data.Set("supported_revocation_auth_methods", mapClientAuthMethodsFromDTO(&dto.SupportedRevocationAuthMethods))
	data.Set("introspection_endpoint", dto.IntrospectionEndpoint)
	data.Set("direct_introspection_endpoint_enabled", dto.DirectIntrospectionEndpointEnabled)
	data.Set("supported_introspection_auth_methods", mapClientAuthMethodsFromDTO(&dto.SupportedIntrospectionAuthMethods))
	data.Set("pushed_auth_req_endpoint", dto.PushedAuthReqEndpoint)
	data.Set("pushed_auth_req_duration", dto.PushedAuthReqDuration)
	data.Set("par_required", dto.ParRequired)
	data.Set("request_object_required", dto.RequestObjectRequired)
	data.Set("traditional_request_object_processing_applied", dto.TraditionalRequestObjectProcessingApplied)
	data.Set("nbf_optional", dto.NbfOptional)
	data.Set("front_channel_encryption_request_obj_required", dto.FrontChannelRequestObjectEncryptionRequired)
	data.Set("encryption_alg_req_obj_match", dto.RequestObjectEncryptionAlgMatchRequired)
	data.Set("encryption_enc_alg_req_obj_match", dto.RequestObjectEncryptionEncMatchRequired)
	data.Set("access_token_type", dto.AccessTokenType)
	data.Set("tls_client_certificate_bound_access_tokens", dto.TlsClientCertificateBoundAccessTokens)
	data.Set("access_token_duration", dto.AccessTokenDuration)
	data.Set("single_access_token_per_subject", dto.SingleAccessTokenPerSubject)
	data.Set("access_token_sign_alg", dto.AccessTokenSignAlg)
	data.Set("access_token_signature_key_id", dto.AccessTokenSignatureKeyId)
	data.Set("refresh_token_duration", dto.RefreshTokenDuration)
	data.Set("refresh_token_duration_kept", dto.RefreshTokenDurationKept)
	data.Set("refresh_token_duration_reset", dto.RefreshTokenDurationReset)
	data.Set("refresh_token_kept", dto.RefreshTokenKept)
	data.Set("token_expiration_link", dto.TokenExpirationLinked)
	data.Set("supported_scopes", mapSupportedScopeFromDTO(&dto.SupportedScopes))
	data.Set("scope_required", dto.ScopeRequired)
	data.Set("id_token_duration", dto.IdTokenDuration)
	data.Set("allowable_clock_skew", dto.AllowableClockSkew)
	data.Set("supported_claim_types", mapClaimTypesFromDTO(&dto.SupportedClaimTypes))
	data.Set("supported_claim_locales", mapSchemaFromString(&dto.SupportedClaimLocales))
	data.Set("supported_claims", mapSchemaFromString(&dto.SupportedClaims))
	data.Set("claim_shortcut_restrictive", dto.ClaimShortcutRestrictive)
	data.Set("jwks_endpoint", dto.JwksUri)
	data.Set("direct_jwks_endpoint_enabled", dto.DirectJwksEndpointEnabled)
	jwk, err := mapJWKFromDTO(data.Get("jwk").([]interface{}), dto.Jwks)
	if err != nil {
		return diag.FromErr(err)
	}
	data.Set("jwk", jwk)
	data.Set("id_token_signature_key_id", dto.IdTokenSignatureKeyId)
	data.Set("user_info_signature_key_id", dto.UserInfoSignatureKeyId)
	data.Set("authorization_signature_key_id", dto.AuthorizationSignatureKeyId)
	data.Set("hsm_enabled", dto.HsmEnabled)
	data.Set("user_info_endpoint", dto.UserInfoEndpoint)
	data.Set("direct_user_info_endpoint_enabled", dto.DirectUserInfoEndpointEnabled)
	data.Set("dynamic_registration_supported", dto.DynamicRegistrationSupported)
	// data.Set("dcr_scope_used_as_requestable", dto.DcrScopeUsedAsRequestable)
	data.Set("registration_endpoint", dto.RegistrationEndpoint)
	data.Set("registration_management_endpoint", dto.RegistrationManagementEndpoint)
	data.Set("mtls_endpoint_aliases", mapMtlsEndpointFromDTO(&dto.MtlsEndpointAliases))
	data.Set("policy_uri", dto.PolicyUri)
	data.Set("tos_uri", dto.TosUri)
	data.Set("service_documentation", dto.ServiceDocumentation)
	data.Set("backchannel_authentication_endpoint", dto.BackchannelAuthenticationEndpoint)
	data.Set("supported_backchannel_token_delivery_modes", mapBackchannelDeliveryFromDTO(&dto.SupportedBackchannelTokenDeliveryModes))
	data.Set("backchannel_auth_req_id_duration", dto.BackchannelAuthReqIdDuration)
	data.Set("backcannel_polling_interval", dto.BachcannelPollingInterval)
	data.Set("backchannel_user_code_parameter_supported", dto.BackchannelUserCodeParameterSupported)
	data.Set("backchannel_binding_message_required_in_fapi", dto.BackchannelBindingMessageRequiredInFapi)
	data.Set("device_authorization_endpoint", dto.DeviceAuthorizationEndpoint)
	data.Set("device_verification_uri", dto.DeviceVerificationUri)
	data.Set("device_verification_uri_complete", dto.DeviceVerificationUriComplete)
	data.Set("device_flow_code_duration", dto.DeviceFlowCodeDuration)
	data.Set("device_flow_polling_interval", dto.DeviceFlowPollingInterval)
	data.Set("user_code_charset", mapUserCodeCharsetsFromDTO(dto.UserCodeCharset))
	data.Set("user_code_length", dto.UserCodeLength)

	/*
		data.Set("supported_trust_frameworks", mapSchemaFromString(&dto.SupportedTrustFrameworks))
		data.Set("supported_evidence", mapSchemaFromString(&dto.SupportedEvidence))
		data.Set("supported_identity_documents", mapSchemaFromString(&dto.SupportedIdentityDocuments))
		data.Set("supported_verification_methods", mapSchemaFromString(&dto.SupportedVerificationMethods))
		data.Set("supported_verified_claims", mapSchemaFromString(&dto.SupportedVerifiedClaims))
	*/
	data.Set("end_session_endpoint", dto.EndSessionEndpoint)
	return nil
}

func mapSetToString(vals []interface{}) []string {
	values := make([]string, len(vals))

	for i, v := range vals {
		values[i] = v.(string)
	}

	return values
}

func mapSchemaFromString(vals *[]string) []interface{} {
	if vals != nil {
		entries := make([]interface{}, len(*vals), len(*vals))
		for i, v := range *vals {
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
