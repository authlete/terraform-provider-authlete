package provider

import (
	"context"
	"strconv"

	"github.com/authlete/authlete-go-openapi"
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
			"apikey":                     {Type: schema.TypeString, Required: false, Optional: true},
			"apisecret":                  {Type: schema.TypeString, Required: false, Optional: true, Sensitive: true},
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

	if d.Get("apikey") != "" && client.api_key != d.Get("apikey") {
		apiKey = d.Get("apikey").(string)
		apiSecret = d.Get("apisecret").(string)
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

	if d.Get("apikey") != "" && client.api_key != d.Get("apikey") {
		apiKey = d.Get("apikey").(string)
		apiSecret = d.Get("apisecret").(string)
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

	if d.Get("apikey") != "" && client.api_key != d.Get("apikey") {
		apiKey = d.Get("apikey").(string)
		apiSecret = d.Get("apisecret").(string)
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

	if d.Get("apikey") != "" && client.api_key != d.Get("apikey") {
		apiKey = d.Get("apikey").(string)
		apiSecret = d.Get("apisecret").(string)
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
	newClient.SetClientIdAlias(d.Get("client_id_alias").(string))
	newClient.SetClientIdAliasEnabled(d.Get("client_id_alias_enabled").(bool))
	newClient.SetClientType(d.Get("client_type").(string))
	newClient.SetRedirectUris(mapSetToString(d.Get("redirect_uris").([]interface{})))
	newClient.SetResponseTypes(mapResponseTypesToDTO(d.Get("response_types").([]interface{})))
	newClient.SetGrantTypes(mapGrantTypesToDTO(d.Get("grant_types").([]interface{})))
	newClient.SetApplicationType(mapApplicationTypeToDto(d.Get("application_type")))
	newClient.SetContacts(mapSetToString(d.Get("contacts").([]interface{})))
	newClient.SetClientName(d.Get("client_name").(string))
	newClient.SetClientNames(mapTaggedValuesToDTO(d.Get("client_names").([]interface{})))
	newClient.SetLogoUri(d.Get("logo_uri").(string))
	newClient.SetLogoUris(mapTaggedValuesToDTO(d.Get("logo_uris").([]interface{})))
	newClient.SetClientUri(d.Get("client_uri").(string))
	newClient.SetClientUris(mapTaggedValuesToDTO(d.Get("client_uris").([]interface{})))
	newClient.SetPolicyUri(d.Get("policy_uri").(string))
	newClient.SetPolicyUris(mapTaggedValuesToDTO(d.Get("policy_uris").([]interface{})))
	newClient.SetTosUri(d.Get("tos_uri").(string))
	newClient.SetTosUris(mapTaggedValuesToDTO(d.Get("tos_uris").([]interface{})))
	newClient.SetJwksUri(d.Get("jwks_uri").(string))
	newClient.SetJwks(d.Get("jwks").(string))
	newClient.SetDerivedSectorIdentifier(d.Get("derived_sector_identifier").(string))
	newClient.SetSectorIdentifierUri(d.Get("sector_identifier_uri").(string))
	newClient.SetSubjectType(mapSubjectTypeToDto(d.Get("subject_type")))
	newClient.SetIdTokenSignAlg(mapJWSAlg(d.Get("id_token_sign_alg")))
	newClient.SetIdTokenEncryptionAlg(mapJWEAlg(d.Get("id_token_encryption_alg")))
	newClient.SetIdTokenEncryptionEnc(mapJWEEnc(d.Get("id_token_encryption_enc")))
	newClient.SetUserInfoSignAlg(mapJWSAlg(d.Get("user_info_sign_alg")))
	newClient.SetUserInfoEncryptionAlg(mapJWEAlg(d.Get("user_info_encryption_alg")))
	newClient.SetUserInfoEncryptionEnc(mapJWEEnc(d.Get("user_info_encryption_enc")))
	newClient.SetRequestSignAlg(mapJWSAlg(d.Get("request_sign_alg")))
	newClient.SetRequestEncryptionAlg(mapJWEAlg(d.Get("request_encryption_alg")))
	newClient.SetRequestEncryptionEnc(mapJWEEnc(d.Get("request_encryption_enc")))
	newClient.SetTokenAuthMethod(mapClientAuthMethodToDto(d.Get("token_auth_method")))
	newClient.SetTokenAuthSignAlg(mapJWSAlg(d.Get("token_auth_sign_alg")))
	newClient.SetDefaultMaxAge(int32(d.Get("default_max_age").(int)))
	newClient.SetDefaultAcrs(mapSetToString(d.Get("default_acrs").([]interface{})))
	newClient.SetAuthTimeRequired(d.Get("auth_time_required").(bool))
	newClient.SetLoginUri(d.Get("login_uri").(string))
	newClient.SetRequestUris(mapSetToString(d.Get("request_uris").([]interface{})))
	newClient.SetDescription(d.Get("description").(string))
	newClient.SetDescriptions(mapTaggedValuesToDTO(d.Get("descriptions").([]interface{})))

	ext := authlete.NewClientExtension()
	ext.SetRequestableScopesEnabled(d.Get("requestable_scopes_enabled").(bool))
	ext.SetRequestableScopes(mapSetToString(d.Get("requestable_scopes").([]interface{})))
	ext.SetAccessTokenDuration(int64(d.Get("access_token_duration").(int)))
	ext.SetRefreshTokenDuration(int64(d.Get("refresh_token_duration").(int)))
	newClient.SetExtension(*ext)

	newClient.SetTlsClientAuthSubjectDn(d.Get("tls_client_auth_subject_dn").(string))
	newClient.SetTlsClientAuthSanDns(d.Get("tls_client_auth_san_dns").(string))
	newClient.SetTlsClientAuthSanUri(d.Get("tls_client_auth_san_uri").(string))
	newClient.SetTlsClientAuthSanIp(d.Get("tls_client_auth_san_ip").(string))
	newClient.SetTlsClientAuthSanEmail(d.Get("tls_client_auth_san_email").(string))
	newClient.SetTlsClientCertificateBoundAccessTokens(d.Get("tls_client_certificate_bound_access_tokens").(bool))
	newClient.SetSelfSignedCertificateKeyId(d.Get("self_signed_certificate_key_id").(string))
	newClient.SetSoftwareId(d.Get("software_id").(string))
	newClient.SetSoftwareVersion(d.Get("software_version").(string))
	newClient.SetAuthorizationSignAlg(mapJWSAlg(d.Get("authorization_sign_alg")))
	newClient.SetAuthorizationEncryptionAlg(mapJWEAlg(d.Get("authorization_encryption_alg")))
	newClient.SetAuthorizationEncryptionEnc(mapJWEEnc(d.Get("authorization_encryption_enc")))
	newClient.SetBcDeliveryMode(d.Get("bc_delivery_mode").(string))
	newClient.SetBcNotificationEndpoint(d.Get("bc_notification_endpoint").(string))
	newClient.SetBcRequestSignAlg(mapJWSAlg(d.Get("bc_request_sign_alg")))
	newClient.SetBcUserCodeRequired(d.Get("bc_user_code_required").(bool))
	newClient.SetDynamicallyRegistered(d.Get("dynamically_registered").(bool))
	newClient.SetRegistrationAccessTokenHash(d.Get("registration_access_token_hash").(string))
	newClient.SetAuthorizationDetailsTypes(mapSetToString(d.Get("authorization_details_types").([]interface{})))
	newClient.SetParRequired(d.Get("par_required").(bool))
	newClient.SetRequestObjectRequired(d.Get("request_object_required").(bool))
	newClient.SetAttributes(mapAttributesToDTO(d.Get("attributes").([]interface{})))
	newClient.SetCustomMetadata(d.Get("custom_metadata").(string))
	newClient.SetFrontChannelRequestObjectEncryptionRequired(d.Get("front_channel_request_object_encryption_required").(bool))
	newClient.SetRequestObjectEncryptionAlgMatchRequired(d.Get("request_object_encryption_alg_match_required").(bool))
	newClient.SetRequestObjectEncryptionEncMatchRequired(d.Get("request_object_encryption_enc_match_required").(bool))

	return newClient
}

func updateResourceFromClient(d *schema.ResourceData, client *authlete.Client) {
	d.Set("developer", client.Developer)
	d.Set("client_id", client.ClientId)
	d.Set("client_secret", client.ClientSecret)
	d.Set("client_id_alias", client.ClientIdAlias)
	d.Set("client_id_alias_enabled", client.ClientIdAliasEnabled)
	d.Set("client_type", client.ClientType)
	d.Set("redirect_uris", client.RedirectUris)
	d.Set("grant_types", client.GrantTypes)
	d.Set("response_types", client.ResponseTypes)
	d.Set("application_type", client.ApplicationType)
	d.Set("contacts", client.Contacts)
	d.Set("client_name", client.ClientName)
	d.Set("client_names", client.ClientNames)
	d.Set("logo_uri", client.LogoUri)
	d.Set("logo_uris", mapTaggedValuesFromDTO(client.LogoUris))
	d.Set("client_uri", client.ClientUri)
	d.Set("client_uris", mapTaggedValuesFromDTO(client.ClientUris))
	d.Set("policy_uri", client.PolicyUri)
	d.Set("policy_uris", mapTaggedValuesFromDTO(client.PolicyUris))
	d.Set("tos_uri", client.TosUri)
	d.Set("tos_uris", mapTaggedValuesFromDTO(client.TosUris))
	d.Set("jwks_uri", client.JwksUri)
	d.Set("jwks", client.Jwks)
	d.Set("derived_sector_identifier", client.DerivedSectorIdentifier)
	d.Set("sector_identifier_uri", client.SectorIdentifierUri)
	d.Set("subject_type", client.SubjectType)
	d.Set("id_token_sign_alg", client.IdTokenSignAlg)
	d.Set("id_token_encryption_alg", client.IdTokenEncryptionAlg)
	d.Set("id_token_encryption_enc", client.IdTokenEncryptionEnc)
	d.Set("user_info_sign_alg", client.UserInfoSignAlg)
	d.Set("user_info_encryption_alg", client.UserInfoEncryptionAlg)
	d.Set("user_info_encryption_enc", client.UserInfoEncryptionEnc)
	d.Set("request_sign_alg", client.RequestSignAlg)
	d.Set("request_encryption_alg", client.RequestEncryptionAlg)
	d.Set("request_encryption_enc", client.RequestEncryptionEnc)
	d.Set("token_auth_method", client.TokenAuthMethod)
	d.Set("token_auth_sign_alg", client.TokenAuthSignAlg)
	d.Set("default_max_age", client.DefaultMaxAge)
	d.Set("default_acrs", client.DefaultAcrs)
	d.Set("auth_time_required", client.AuthTimeRequired)
	d.Set("login_uri", client.LoginUri)
	d.Set("request_uris", client.RequestUris)
	d.Set("description", client.Description)
	d.Set("descriptions", mapTaggedValuesFromDTO(client.Descriptions))
	d.Set("created_at", client.CreatedAt)
	d.Set("modified_at", client.ModifiedAt)
	d.Set("requestable_scopes_enabled", client.Extension.RequestableScopesEnabled)
	d.Set("requestable_scopes", client.Extension.RequestableScopes)
	d.Set("access_token_duration", client.Extension.AccessTokenDuration)
	d.Set("refresh_token_duration", client.Extension.RefreshTokenDuration)
	d.Set("tls_client_auth_subject_dn", client.TlsClientAuthSubjectDn)
	d.Set("tls_client_auth_san_dns", client.TlsClientAuthSanDns)
	d.Set("tls_client_auth_san_uri", client.TlsClientAuthSanUri)
	d.Set("tls_client_auth_san_ip", client.TlsClientAuthSanIp)
	d.Set("tls_client_auth_san_email", client.TlsClientAuthSanEmail)
	d.Set("tls_client_certificate_bound_access_tokens", client.TlsClientCertificateBoundAccessTokens)
	d.Set("self_signed_certificate_key_id", client.SelfSignedCertificateKeyId)
	d.Set("software_id", client.SoftwareId)
	d.Set("software_version", client.SoftwareVersion)
	d.Set("authorization_sign_alg", client.AuthorizationSignAlg)
	d.Set("authorization_encryption_alg", client.AuthorizationEncryptionAlg)
	d.Set("authorization_encryption_enc", client.AuthorizationEncryptionEnc)
	d.Set("bc_delivery_mode", client.BcDeliveryMode)
	d.Set("bc_notification_endpoint", client.BcNotificationEndpoint)
	d.Set("bc_request_sign_alg", client.BcRequestSignAlg)
	d.Set("bc_user_code_required", client.BcUserCodeRequired)
	d.Set("dynamically_registered", client.DynamicallyRegistered)
	d.Set("registration_access_token_hash", client.RegistrationAccessTokenHash)
	d.Set("authorization_details_types", client.AuthorizationDetailsTypes)
	d.Set("par_required", client.ParRequired)
	d.Set("request_object_required", client.RequestObjectRequired)
	d.Set("attributes", mapAttributesFromDTO(client.Attributes))
	d.Set("custom_metadata", client.CustomMetadata)
	d.Set("front_channel_request_object_encryption_required", client.FrontChannelRequestObjectEncryptionRequired)
	d.Set("request_object_encryption_alg_match_required", client.RequestObjectEncryptionAlgMatchRequired)
	d.Set("request_object_encryption_enc_match_required", client.RequestObjectEncryptionAlgMatchRequired)

}
