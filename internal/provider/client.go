package provider

import (
	"context"
	"strconv"

	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func client() *schema.Resource {
	return &schema.Resource{
		Description: `A client in Authlete platform is OAuth client`,

		CreateContext: clientCreate,
		ReadContext:   clientRead,
		UpdateContext: clientUpdate,
		DeleteContext: clientDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"service_api_key":            {Type: schema.TypeString, Required: false, Optional: true},
			"service_api_secret":         {Type: schema.TypeString, Required: false, Optional: true, Sensitive: true},
			"developer":                  {Type: schema.TypeString, Required: true},
			"client_id":                  {Type: schema.TypeInt, Required: false, Optional: true, Computed: true},
			"client_secret":              {Type: schema.TypeString, Required: false, Computed: true, Sensitive: true},
			"client_id_alias":            {Type: schema.TypeString, Required: true},
			"client_id_alias_enabled":    {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"client_type":                createClientTypeSchema(),
			"redirect_uris":              createStringColSchema(),
			"response_types":             createResponseTypeSchema(),
			"grant_types":                createGrantTypeSchema(),
			"application_type":           createApplicationTypeSchema(),
			"contacts":                   createStringColSchema(),
			"client_name":                {Type: schema.TypeString, Required: false, Optional: true},
			"client_names":               createTaggedValuesSchema(),
			"logo_uri":                   {Type: schema.TypeString, Required: false, Optional: true},
			"logo_uris":                  createTaggedValuesSchema(),
			"client_uri":                 {Type: schema.TypeString, Required: false, Optional: true},
			"client_uris":                createTaggedValuesSchema(),
			"policy_uri":                 {Type: schema.TypeString, Required: false, Optional: true},
			"policy_uris":                createTaggedValuesSchema(),
			"tos_uri":                    {Type: schema.TypeString, Required: false, Optional: true},
			"tos_uris":                   createTaggedValuesSchema(),
			"jwks_uri":                   {Type: schema.TypeString, Required: false, Optional: true},
			"jwks":                       {Type: schema.TypeString, Required: false, Optional: true},
			"derived_sector_identifier":  {Type: schema.TypeString, Required: false, Optional: true, Computed: true},
			"sector_identifier_uri":      {Type: schema.TypeString, Required: false, Optional: true},
			"subject_type":               createSubjectTypeSchema(),
			"id_token_sign_alg":          createJWSAlgSchema(),
			"id_token_encryption_alg":    createJWEAlgSchema(),
			"id_token_encryption_enc":    createJWEEncSchema(),
			"user_info_sign_alg":         createJWSAlgSchema(),
			"user_info_encryption_alg":   createJWEAlgSchema(),
			"user_info_encryption_enc":   createJWEEncSchema(),
			"request_sign_alg":           createJWSAlgSchema(),
			"request_encryption_alg":     createJWEAlgSchema(),
			"request_encryption_enc":     createJWEEncSchema(),
			"token_auth_method":          createClientAuthMethodSchema(),
			"token_auth_sign_alg":        createJWSAlgSchema(),
			"default_max_age":            {Type: schema.TypeInt, Required: false, Optional: true},
			"default_acrs":               createStringColSchema(),
			"auth_time_required":         {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"login_uri":                  {Type: schema.TypeString, Required: false, Optional: true},
			"request_uris":               createStringColSchema(),
			"description":                {Type: schema.TypeString, Required: false, Optional: true},
			"descriptions":               createTaggedValuesSchema(),
			"created_at":                 {Type: schema.TypeInt, Required: false, Optional: true, Computed: true},
			"modified_at":                {Type: schema.TypeInt, Required: false, Optional: true, Computed: true},
			"requestable_scopes_enabled": {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"requestable_scopes":         createStringColSchema(),
			"access_token_duration":      {Type: schema.TypeInt, Required: false, Optional: true},
			"refresh_token_duration":     {Type: schema.TypeInt, Required: false, Optional: true},
			"tls_client_auth_subject_dn": {Type: schema.TypeString, Required: false, Optional: true},
			"tls_client_auth_san_dns":    {Type: schema.TypeString, Required: false, Optional: true},
			"tls_client_auth_san_uri":    {Type: schema.TypeString, Required: false, Optional: true},
			"tls_client_auth_san_ip":     {Type: schema.TypeString, Required: false, Optional: true},
			"tls_client_auth_san_email":  {Type: schema.TypeString, Required: false, Optional: true},
			"tls_client_certificate_bound_access_tokens":       {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"self_signed_certificate_key_id":                   {Type: schema.TypeString, Required: false, Optional: true},
			"software_id":                                      {Type: schema.TypeString, Required: false, Optional: true},
			"software_version":                                 {Type: schema.TypeString, Required: false, Optional: true},
			"authorization_sign_alg":                           createJWSAlgSchema(),
			"authorization_encryption_alg":                     createJWEAlgSchema(),
			"authorization_encryption_enc":                     createJWEEncSchema(),
			"bc_delivery_mode":                                 createDeliveryModeSchema(),
			"bc_notification_endpoint":                         {Type: schema.TypeString, Required: false, Optional: true},
			"bc_request_sign_alg":                              createJWSAlgSchema(),
			"bc_user_code_required":                            {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"dynamically_registered":                           {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"registration_access_token_hash":                   {Type: schema.TypeString, Required: false, Optional: true},
			"authorization_details_types":                      createStringColSchema(),
			"par_required":                                     {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"request_object_required":                          {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"attributes":                                       createAttributeSchema(),
			"custom_metadata":                                  {Type: schema.TypeString, Required: false, Optional: true},
			"front_channel_request_object_encryption_required": {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"request_object_encryption_alg_match_required":     {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"request_object_encryption_enc_match_required":     {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
		},
	}
}

func clientCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Trace(ctx, "Creating a new client")
	client := meta.(*apiClient)

	apiKey := client.api_key
	apiSecret := client.api_secret

	if d.Get("service_api_key") != "" && client.api_key != d.Get("service_api_key") {
		apiKey = d.Get("service_api_key").(string)
		apiSecret = d.Get("service_api_secret").(string)
	}

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: apiKey,
		Password: apiSecret,
	})

	newClientDto := dataToClient(d)

	newOauthClient, _, err := client.authleteClient.ClientManagementApi.ClientCreateApi(auth).Client(*newClientDto).Execute()

	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Client created")
	updateResourceFromClient(d, newOauthClient)
	d.SetId(strconv.FormatInt(newOauthClient.GetClientId(), 10))
	return diags
}

func clientRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := meta.(*apiClient)

	apiKey := client.api_key
	apiSecret := client.api_secret

	if d.Get("service_api_key") != "" && client.api_key != d.Get("service_api_key") {
		apiKey = d.Get("service_api_key").(string)
		apiSecret = d.Get("service_api_secret").(string)
	}

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: apiKey,
		Password: apiSecret,
	})

	clientDto, _, err := client.authleteClient.ClientManagementApi.ClientGetApi(auth, d.Id()).Execute()
	if err != nil {
		return diag.FromErr(err)
	}
	updateResourceFromClient(d, clientDto)
	return diags
}

func clientUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics

	tflog.Trace(ctx, "Updating client")
	client := meta.(*apiClient)

	apiKey := client.api_key
	apiSecret := client.api_secret

	if d.Get("service_api_key") != "" && client.api_key != d.Get("service_api_key") {
		apiKey = d.Get("service_api_key").(string)
		apiSecret = d.Get("service_api_secret").(string)
	}

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: apiKey,
		Password: apiSecret,
	})
	newClientDto := dataToClient(d)

	newClient, _, err := client.authleteClient.ClientManagementApi.ClientUpdateApi(auth, d.Id()).Client(*newClientDto).Execute()

	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Client updated")
	updateResourceFromClient(d, newClient)
	d.SetId(strconv.FormatInt(newClient.GetClientId(), 10))
	return diags

}

func clientDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := meta.(*apiClient)

	apiKey := client.api_key
	apiSecret := client.api_secret

	if d.Get("service_api_key") != "" && client.api_key != d.Get("service_api_key") {
		apiKey = d.Get("service_api_key").(string)
		apiSecret = d.Get("service_api_secret").(string)
	}

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: apiKey,
		Password: apiSecret,
	})

	_, err := client.authleteClient.ClientManagementApi.ClientDeleteApi(auth, d.Id()).Execute()
	if err != nil {
		return diag.FromErr(err)
	}
	return diags
}

func dataToClient(d *schema.ResourceData) *authlete.Client {

	newClient := authlete.NewClient()

	newClient.SetDeveloper(d.Get("developer").(string))
	newClient.SetClientId(int64(d.Get("client_id").(int)))

	if NotZeroString(d, "client_id_alias") {
		newClient.SetClientIdAlias(d.Get("client_id_alias").(string))
	}
	newClient.SetClientIdAliasEnabled(d.Get("client_id_alias_enabled").(bool))
	if NotZeroString(d, "client_type") {
		newClient.SetClientType(authlete.ClientType(d.Get("client_type").(string)))
	}
	newClient.SetRedirectUris(mapSetToString(d.Get("redirect_uris").([]interface{})))
	newClient.SetResponseTypes(mapResponseTypesToDTO(d.Get("response_types").([]interface{})))
	newClient.SetGrantTypes(mapGrantTypesToDTO(d.Get("grant_types").([]interface{})))
	if NotZeroString(d, "application_type") {
		newClient.SetApplicationType(mapApplicationTypeToDto(d.Get("application_type")))
	}
	newClient.SetContacts(mapSetToString(d.Get("contacts").([]interface{})))
	if NotZeroString(d, "client_name") {
		newClient.SetClientName(d.Get("client_name").(string))
	}
	newClient.SetClientNames(mapTaggedValuesToDTO(d.Get("client_names").([]interface{})))
	if NotZeroString(d, "logo_uri") {
		newClient.SetLogoUri(d.Get("logo_uri").(string))
	}
	newClient.SetLogoUris(mapTaggedValuesToDTO(d.Get("logo_uris").([]interface{})))
	if NotZeroString(d, "client_uri") {
		newClient.SetClientUri(d.Get("client_uri").(string))
	}
	newClient.SetClientUris(mapTaggedValuesToDTO(d.Get("client_uris").([]interface{})))
	if NotZeroString(d, "policy_uri") {
		newClient.SetPolicyUri(d.Get("policy_uri").(string))
	}
	newClient.SetPolicyUris(mapTaggedValuesToDTO(d.Get("policy_uris").([]interface{})))
	if NotZeroString(d, "tos_uri") {
		newClient.SetTosUri(d.Get("tos_uri").(string))
	}
	newClient.SetTosUris(mapTaggedValuesToDTO(d.Get("tos_uris").([]interface{})))
	if NotZeroString(d, "jwks_uri") {
		newClient.SetJwksUri(d.Get("jwks_uri").(string))
	}
	if NotZeroString(d, "jwks") {
		newClient.SetJwks(d.Get("jwks").(string))
	}
	if NotZeroString(d, "derived_sector_identifier") {
		newClient.SetDerivedSectorIdentifier(d.Get("derived_sector_identifier").(string))
	}
	if NotZeroString(d, "sector_identifier_uri") {
		newClient.SetSectorIdentifierUri(d.Get("sector_identifier_uri").(string))
	}
	if NotZeroString(d, "subject_type") {
		newClient.SetSubjectType(mapSubjectTypeToDto(d.Get("subject_type")))
	}
	if NotZeroString(d, "id_token_sign_alg") {
		newClient.SetIdTokenSignAlg(mapJWSAlg(d.Get("id_token_sign_alg")))
	}
	if NotZeroString(d, "id_token_encryption_alg") {
		newClient.SetIdTokenEncryptionAlg(mapJWEAlg(d.Get("id_token_encryption_alg")))
	}
	if NotZeroString(d, "id_token_encryption_enc") {
		newClient.SetIdTokenEncryptionEnc(mapJWEEnc(d.Get("id_token_encryption_enc")))
	}
	if NotZeroString(d, "user_info_sign_alg") {
		newClient.SetUserInfoSignAlg(mapJWSAlg(d.Get("user_info_sign_alg")))
	}
	if NotZeroString(d, "user_info_encryption_alg") {
		newClient.SetUserInfoEncryptionAlg(mapJWEAlg(d.Get("user_info_encryption_alg")))
	}
	if NotZeroString(d, "user_info_encryption_enc") {
		newClient.SetUserInfoEncryptionEnc(mapJWEEnc(d.Get("user_info_encryption_enc")))
	}
	if NotZeroString(d, "request_sign_alg") {
		newClient.SetRequestSignAlg(mapJWSAlg(d.Get("request_sign_alg")))
	}
	if NotZeroString(d, "request_encryption_alg") {
		newClient.SetRequestEncryptionAlg(mapJWEAlg(d.Get("request_encryption_alg")))
	}
	if NotZeroString(d, "request_encryption_enc") {
		newClient.SetRequestEncryptionEnc(mapJWEEnc(d.Get("request_encryption_enc")))
	}
	if NotZeroString(d, "token_auth_method") {
		newClient.SetTokenAuthMethod(mapClientAuthMethodToDto(d.Get("token_auth_method")))
	}
	if NotZeroString(d, "token_auth_sign_alg") {
		newClient.SetTokenAuthSignAlg(mapJWSAlg(d.Get("token_auth_sign_alg")))
	}
	newClient.SetDefaultMaxAge(int32(d.Get("default_max_age").(int)))
	newClient.SetDefaultAcrs(mapSetToString(d.Get("default_acrs").([]interface{})))
	newClient.SetAuthTimeRequired(d.Get("auth_time_required").(bool))
	if NotZeroString(d, "login_uri") {
		newClient.SetLoginUri(d.Get("login_uri").(string))
	}
	newClient.SetRequestUris(mapSetToString(d.Get("request_uris").([]interface{})))
	if NotZeroString(d, "description") {
		newClient.SetDescription(d.Get("description").(string))
	}
	newClient.SetDescriptions(mapTaggedValuesToDTO(d.Get("descriptions").([]interface{})))

	ext := authlete.NewClientExtension()
	ext.SetRequestableScopesEnabled(d.Get("requestable_scopes_enabled").(bool))
	ext.SetRequestableScopes(mapSetToString(d.Get("requestable_scopes").([]interface{})))
	ext.SetAccessTokenDuration(int64(d.Get("access_token_duration").(int)))
	ext.SetRefreshTokenDuration(int64(d.Get("refresh_token_duration").(int)))
	newClient.SetExtension(*ext)

	if NotZeroString(d, "tls_client_auth_subject_dn") {
		newClient.SetTlsClientAuthSubjectDn(d.Get("tls_client_auth_subject_dn").(string))
	}
	if NotZeroString(d, "tls_client_auth_san_dns") {
		newClient.SetTlsClientAuthSanDns(d.Get("tls_client_auth_san_dns").(string))
	}
	if NotZeroString(d, "tls_client_auth_san_uri") {
		newClient.SetTlsClientAuthSanUri(d.Get("tls_client_auth_san_uri").(string))
	}
	if NotZeroString(d, "tls_client_auth_san_ip") {
		newClient.SetTlsClientAuthSanIp(d.Get("tls_client_auth_san_ip").(string))
	}
	if NotZeroString(d, "tls_client_auth_san_email") {
		newClient.SetTlsClientAuthSanEmail(d.Get("tls_client_auth_san_email").(string))
	}
	newClient.SetTlsClientCertificateBoundAccessTokens(d.Get("tls_client_certificate_bound_access_tokens").(bool))
	if NotZeroString(d, "self_signed_certificate_key_id") {
		newClient.SetSelfSignedCertificateKeyId(d.Get("self_signed_certificate_key_id").(string))
	}
	if NotZeroString(d, "software_id") {
		newClient.SetSoftwareId(d.Get("software_id").(string))
	}
	if NotZeroString(d, "software_version") {
		newClient.SetSoftwareVersion(d.Get("software_version").(string))
	}
	if NotZeroString(d, "authorization_sign_alg") {
		newClient.SetAuthorizationSignAlg(mapJWSAlg(d.Get("authorization_sign_alg")))
	}
	if NotZeroString(d, "authorization_encryption_alg") {
		newClient.SetAuthorizationEncryptionAlg(mapJWEAlg(d.Get("authorization_encryption_alg")))
	}
	if NotZeroString(d, "authorization_encryption_enc") {
		newClient.SetAuthorizationEncryptionEnc(mapJWEEnc(d.Get("authorization_encryption_enc")))
	}
	if NotZeroString(d, "bc_delivery_mode") {
		newClient.SetBcDeliveryMode(d.Get("bc_delivery_mode").(string))
	}
	if NotZeroString(d, "bc_notification_endpoint") {
		newClient.SetBcNotificationEndpoint(d.Get("bc_notification_endpoint").(string))
	}
	if NotZeroString(d, "bc_request_sign_alg") {
		newClient.SetBcRequestSignAlg(mapJWSAlg(d.Get("bc_request_sign_alg")))
	}
	newClient.SetBcUserCodeRequired(d.Get("bc_user_code_required").(bool))
	newClient.SetDynamicallyRegistered(d.Get("dynamically_registered").(bool))
	if NotZeroString(d, "registration_access_token_hash") {
		newClient.SetRegistrationAccessTokenHash(d.Get("registration_access_token_hash").(string))
	}
	newClient.SetAuthorizationDetailsTypes(mapSetToString(d.Get("authorization_details_types").([]interface{})))
	newClient.SetParRequired(d.Get("par_required").(bool))
	newClient.SetRequestObjectRequired(d.Get("request_object_required").(bool))
	newClient.SetAttributes(mapAttributesToDTO(d.Get("attributes").([]interface{})))
	if NotZeroString(d, "custom_metadata") {
		newClient.SetCustomMetadata(d.Get("custom_metadata").(string))
	}
	newClient.SetFrontChannelRequestObjectEncryptionRequired(d.Get("front_channel_request_object_encryption_required").(bool))
	newClient.SetRequestObjectEncryptionAlgMatchRequired(d.Get("request_object_encryption_alg_match_required").(bool))
	newClient.SetRequestObjectEncryptionEncMatchRequired(d.Get("request_object_encryption_enc_match_required").(bool))

	return newClient
}

func updateResourceFromClient(d *schema.ResourceData, client *authlete.Client) {
	d.Set("developer", client.GetDeveloper())
	d.Set("client_id", client.GetClientId())
	d.Set("client_secret", client.GetClientSecret())
	d.Set("client_id_alias", client.GetClientIdAlias())
	d.Set("client_id_alias_enabled", client.GetClientIdAliasEnabled())
	d.Set("client_type", client.GetClientType())
	d.Set("redirect_uris", client.GetRedirectUris())
	d.Set("grant_types", client.GetGrantTypes())
	d.Set("response_types", client.GetResponseTypes())
	d.Set("application_type", client.GetApplicationType())
	d.Set("contacts", client.GetContacts())
	d.Set("client_name", client.GetClientName())
	d.Set("client_names", client.GetClientNames())
	d.Set("logo_uri", client.GetLogoUri())
	d.Set("logo_uris", mapTaggedValuesFromDTO(client.GetLogoUris()))
	d.Set("client_uri", client.GetClientUri())
	d.Set("client_uris", mapTaggedValuesFromDTO(client.GetClientUris()))
	d.Set("policy_uri", client.GetPolicyUri())
	d.Set("policy_uris", mapTaggedValuesFromDTO(client.GetPolicyUris()))
	d.Set("tos_uri", client.GetTosUri())
	d.Set("tos_uris", mapTaggedValuesFromDTO(client.GetTosUris()))
	d.Set("jwks_uri", client.GetJwksUri())
	d.Set("jwks", client.GetJwks())
	d.Set("derived_sector_identifier", client.GetDerivedSectorIdentifier())
	d.Set("sector_identifier_uri", client.GetSectorIdentifierUri())
	d.Set("subject_type", client.GetSubjectType())
	d.Set("id_token_sign_alg", client.GetIdTokenSignAlg())
	d.Set("id_token_encryption_alg", client.GetIdTokenEncryptionAlg())
	d.Set("id_token_encryption_enc", client.GetIdTokenEncryptionEnc())
	d.Set("user_info_sign_alg", client.GetUserInfoSignAlg())
	d.Set("user_info_encryption_alg", client.GetUserInfoEncryptionAlg())
	d.Set("user_info_encryption_enc", client.GetUserInfoEncryptionEnc())
	d.Set("request_sign_alg", client.GetRequestSignAlg())
	d.Set("request_encryption_alg", client.GetRequestEncryptionAlg())
	d.Set("request_encryption_enc", client.GetRequestEncryptionEnc())
	d.Set("token_auth_method", client.GetTokenAuthMethod())
	d.Set("token_auth_sign_alg", client.GetTokenAuthSignAlg())
	d.Set("default_max_age", client.GetDefaultMaxAge())
	d.Set("default_acrs", client.GetDefaultAcrs())
	d.Set("auth_time_required", client.GetAuthTimeRequired())
	d.Set("login_uri", client.GetLoginUri())
	d.Set("request_uris", client.GetRequestUris())
	d.Set("description", client.GetDescription())
	d.Set("descriptions", mapTaggedValuesFromDTO(client.GetDescriptions()))
	d.Set("created_at", client.GetCreatedAt())
	d.Set("modified_at", client.GetModifiedAt())
	clientExtension := client.GetExtension()
	d.Set("requestable_scopes_enabled", clientExtension.GetRequestableScopesEnabled())
	d.Set("requestable_scopes", clientExtension.GetRequestableScopes())
	d.Set("access_token_duration", clientExtension.GetAccessTokenDuration())
	d.Set("refresh_token_duration", clientExtension.GetRefreshTokenDuration())
	d.Set("tls_client_auth_subject_dn", client.GetTlsClientAuthSubjectDn())
	d.Set("tls_client_auth_san_dns", client.GetTlsClientAuthSanDns())
	d.Set("tls_client_auth_san_uri", client.GetTlsClientAuthSanUri())
	d.Set("tls_client_auth_san_ip", client.GetTlsClientAuthSanIp())
	d.Set("tls_client_auth_san_email", client.GetTlsClientAuthSanEmail())
	d.Set("tls_client_certificate_bound_access_tokens", client.GetTlsClientCertificateBoundAccessTokens())
	d.Set("self_signed_certificate_key_id", client.GetSelfSignedCertificateKeyId())
	d.Set("software_id", client.GetSoftwareId())
	d.Set("software_version", client.GetSoftwareVersion())
	d.Set("authorization_sign_alg", client.GetAuthorizationSignAlg())
	d.Set("authorization_encryption_alg", client.GetAuthorizationEncryptionAlg())
	d.Set("authorization_encryption_enc", client.GetAuthorizationEncryptionEnc())
	d.Set("bc_delivery_mode", client.GetBcDeliveryMode())
	d.Set("bc_notification_endpoint", client.GetBcNotificationEndpoint())
	d.Set("bc_request_sign_alg", client.GetBcRequestSignAlg())
	d.Set("bc_user_code_required", client.GetBcUserCodeRequired())
	d.Set("dynamically_registered", client.GetDynamicallyRegistered())
	d.Set("registration_access_token_hash", client.GetRegistrationAccessTokenHash())
	d.Set("authorization_details_types", client.GetAuthorizationDetailsTypes())
	d.Set("par_required", client.GetParRequired())
	d.Set("request_object_required", client.GetRequestObjectRequired())
	d.Set("attributes", mapAttributesFromDTO(client.GetAttributes()))
	d.Set("custom_metadata", client.GetCustomMetadata())
	d.Set("front_channel_request_object_encryption_required", client.GetFrontChannelRequestObjectEncryptionRequired())
	d.Set("request_object_encryption_alg_match_required", client.GetRequestObjectEncryptionAlgMatchRequired())
	d.Set("request_object_encryption_enc_match_required", client.GetRequestObjectEncryptionAlgMatchRequired())

}
