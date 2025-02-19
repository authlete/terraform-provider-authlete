package provider

import (
	"context"
	"fmt"
	"strconv"

	authlete3 "github.com/authlete/openapi-for-go/v3"
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
			"service_api_key": {Type: schema.TypeString, Required: false, Optional: true},
			"client_id":       {Type: schema.TypeInt, Required: false, Optional: true, Computed: true},
			"client_secret": {Type: schema.TypeString,
				Required: false, Optional: true, Computed: true, Sensitive: true,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(string)
					if len(v) > 86 {
						errs = append(errs, fmt.Errorf("%q must be shorter than 86 chars long, got: %s", key, v))
					}
					return
				}},
			"client_id_alias":            {Type: schema.TypeString, Required: false, Optional: true},
			"client_id_alias_enabled":    {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"client_type":                createClientTypeSchema(),
			"redirect_uris":              createStringColSchema(),
			"response_types":             createResponseTypeSchema(true),
			"grant_types":                createGrantTypeSchema(true),
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
			"jwk":                        createJWKSchema(),
			"derived_sector_identifier":  {Type: schema.TypeString, Required: false, Optional: true, Computed: true},
			"sector_identifier_uri":      {Type: schema.TypeString, Required: false, Optional: true},
			"subject_type":               createSubjectTypeSchema(),
			"pkce_required":              {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"pkce_s256_required":         {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
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
			"custom_metadata":                                  {Type: schema.TypeString, Required: false, Optional: true, Computed: true},
			"front_channel_request_object_encryption_required": {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"request_object_encryption_alg_match_required":     {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"request_object_encryption_enc_match_required":     {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"digest_algorithm":                                 {Type: schema.TypeString, Required: false, Optional: true},
			"single_access_token_per_subject":                  {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"client_identifier":                                {Type: schema.TypeString, Required: false, Optional: false, Computed: true},
			"dpop_required":                                    {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
		},
	}
}

func clientCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Trace(ctx, "Creating a new client")
	client := meta.(*apiClient)

	apiKey := client.apiKey
	apiSecret := client.apiSecret

	if d.Get("service_api_key") != "" && client.apiKey != d.Get("service_api_key") {
		apiKey = d.Get("service_api_key").(string)
		apiSecret = d.Get("service_api_secret").(string)
	}

	auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, apiSecret)

	newClientDto := dataToClient(d, diags)
	n := newClientDto
	newOauthClient, _, err := client.authleteClient.v3.ClientManagementAPI.ClientCreateApi(auth, apiKey).Client(n).Execute()
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Client created")
	if d.Get("client_secret").(string) != "" {
		cliSecretUpdateRequest := authlete3.ClientSecretUpdateRequest{ClientSecret: d.Get("client_secret").(string)}
		identifier := strconv.FormatInt(newOauthClient.GetClientId(), 10)
		updateSecretRequest := client.authleteClient.v3.ClientManagementAPI.ClientSecretUpdateApi(auth,
			identifier, apiKey)

		_, _, err := updateSecretRequest.ClientSecretUpdateRequest(cliSecretUpdateRequest).Execute()
		if err != nil {
			return diag.FromErr(err)
		}
		newOauthClient.SetClientSecret(d.Get("client_secret").(string))
	}

	updateResourceFromClient(d, *newOauthClient)
	d.Set("client_identifier", strconv.FormatInt(newOauthClient.GetClientId(), 10))
	d.SetId(strconv.FormatInt(newOauthClient.GetClientId(), 10))
	return diags

}

func clientRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	client := meta.(*apiClient)

	apiKey := client.apiKey
	apiSecret := client.apiSecret

	if d.Get("service_api_key") != "" && client.apiKey != d.Get("service_api_key") {
		apiKey = d.Get("service_api_key").(string)

	}

	auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, apiSecret)

	identifier := getClientIdentifierForV3(d)
	clientDto, _, err := client.authleteClient.v3.ClientManagementAPI.ClientGetApi(auth, identifier, apiKey).Execute()
	if err != nil {
		return diag.FromErr(err)
	}
	updateResourceFromClient(d, *clientDto)
	return diags

}

func clientUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics

	tflog.Trace(ctx, "Updating client")
	client := meta.(*apiClient)

	apiKey := client.apiKey
	apiSecret := client.apiSecret

	if d.Get("service_api_key") != "" && client.apiKey != d.Get("service_api_key") {
		apiKey = d.Get("service_api_key").(string)

	}

	auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, apiSecret)

	identifier := getClientIdentifierForV3(d)
	existingClient, _, getErr := client.authleteClient.v3.ClientManagementAPI.ClientGetApi(auth, identifier, apiKey).Execute()

	if getErr != nil {
		return diag.FromErr(getErr)
	}
	setDataToClient(d, diags, *existingClient)
	_, _, err := client.authleteClient.v3.ClientManagementAPI.ClientUpdateApi(auth, identifier, apiKey).Client(*existingClient).Execute()

	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Client updated")

	if d.HasChange("client_secret") {
		if d.Get("client_secret").(string) != "" {
			cliSecretUpdateRequest := authlete3.ClientSecretUpdateRequest{ClientSecret: d.Get("client_secret").(string)}
			updateSecretRequest := client.authleteClient.v3.ClientManagementAPI.ClientSecretUpdateApi(auth, identifier, apiKey)

			_, _, err := updateSecretRequest.ClientSecretUpdateRequest(cliSecretUpdateRequest).Execute()

			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	updateResourceFromClient(d, *existingClient)
	d.Set("client_identifier", strconv.FormatInt(existingClient.GetClientId(), 10))
	return diags

}

func clientDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := meta.(*apiClient)

	apiKey := client.apiKey
	apiSecret := client.apiSecret

	if d.Get("service_api_key") != "" && client.apiKey != d.Get("service_api_key") {
		apiKey = d.Get("service_api_key").(string)

	}

	auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, apiSecret)

	identifier := getClientIdentifierForV3(d)
	_, err := client.authleteClient.v3.ClientManagementAPI.ClientDeleteApi(auth, identifier, apiKey).Execute()
	if err != nil {
		return diag.FromErr(err)
	}
	return diags

}

func dataToClient(d *schema.ResourceData, diags diag.Diagnostics) authlete3.Client {

	newClient := authlete3.NewClient()

	newClient.SetClientId(int64(d.Get("client_id").(int)))

	if NotZeroString(d, "client_id_alias") {
		newClient.SetClientIdAlias(d.Get("client_id_alias").(string))
	}
	newClient.SetClientIdAliasEnabled(d.Get("client_id_alias_enabled").(bool))
	if NotZeroString(d, "client_type") {

		newClient.SetClientType(authlete3.ClientType(d.Get("client_type").(string)))
	}
	newClient.SetRedirectUris(mapSetToString(d.Get("redirect_uris").(*schema.Set).List()))

	newClient.SetResponseTypes(mapListToDTO[authlete3.ResponseType](d.Get("response_types").(*schema.Set).List()))
	newClient.SetGrantTypes(mapSetToDTO[authlete3.GrantType](d.Get("grant_types").(*schema.Set)))
	if NotZeroString(d, "application_type") {
		newClient.SetApplicationType(mapInterfaceToType[authlete3.ApplicationType](d.Get("application_type")))
	}
	newClient.SetClientNames(mapTaggedValuesToDTOV3(d.Get("client_names").(*schema.Set).List()))
	newClient.SetLogoUris(mapTaggedValuesToDTOV3(d.Get("logo_uris").(*schema.Set).List()))
	newClient.SetClientUris(mapTaggedValuesToDTOV3(d.Get("client_uris").(*schema.Set).List()))
	newClient.SetPolicyUris(mapTaggedValuesToDTOV3(d.Get("policy_uris").(*schema.Set).List()))
	newClient.SetTosUris(mapTaggedValuesToDTOV3(d.Get("tos_uris").(*schema.Set).List()))
	if NotZeroString(d, "subject_type") {
		newClient.SetSubjectType(mapInterfaceToType[authlete3.SubjectType](d.Get("subject_type")))
	}
	if NotZeroString(d, "id_token_sign_alg") {
		newClient.SetIdTokenSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("id_token_sign_alg")))
	}
	if NotZeroString(d, "id_token_encryption_alg") {
		newClient.SetIdTokenEncryptionAlg(mapInterfaceToType[authlete3.JweAlg](d.Get("id_token_encryption_alg")))
	}
	if NotZeroString(d, "id_token_encryption_enc") {
		newClient.SetIdTokenEncryptionEnc(mapInterfaceToType[authlete3.JweEnc](d.Get("id_token_encryption_enc")))
	}
	if NotZeroString(d, "user_info_sign_alg") {
		newClient.SetUserInfoSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("user_info_sign_alg")))
	}
	if NotZeroString(d, "user_info_encryption_alg") {
		newClient.SetUserInfoEncryptionAlg(mapInterfaceToType[authlete3.JweAlg](d.Get("user_info_encryption_alg")))
	}
	if NotZeroString(d, "user_info_encryption_enc") {
		newClient.SetUserInfoEncryptionEnc(mapInterfaceToType[authlete3.JweEnc](d.Get("user_info_encryption_enc")))
	}
	if NotZeroString(d, "request_sign_alg") {
		newClient.SetRequestSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("request_sign_alg")))
	}
	if NotZeroString(d, "request_encryption_alg") {
		newClient.SetRequestEncryptionAlg(mapInterfaceToType[authlete3.JweAlg](d.Get("request_encryption_alg")))
	}
	if NotZeroString(d, "request_encryption_enc") {
		newClient.SetRequestEncryptionEnc(mapInterfaceToType[authlete3.JweEnc](d.Get("request_encryption_enc")))
	}
	if NotZeroString(d, "token_auth_method") {
		newClient.SetTokenAuthMethod(mapInterfaceToType[authlete3.ClientAuthMethod](d.Get("token_auth_method")))
	}
	if NotZeroString(d, "token_auth_sign_alg") {
		newClient.SetTokenAuthSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("token_auth_sign_alg")))
	}
	newClient.SetDescriptions(mapTaggedValuesToDTOV3(d.Get("descriptions").(*schema.Set).List()))
	ext := authlete3.NewClientExtension()
	ext.SetRequestableScopesEnabled(d.Get("requestable_scopes_enabled").(bool))
	ext.SetRequestableScopes(mapSetToString(d.Get("requestable_scopes").(*schema.Set).List()))
	ext.SetAccessTokenDuration(int64(d.Get("access_token_duration").(int)))
	ext.SetRefreshTokenDuration(int64(d.Get("refresh_token_duration").(int)))
	newClient.SetExtension(*ext)
	if NotZeroString(d, "authorization_sign_alg") {
		newClient.SetAuthorizationSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("authorization_sign_alg")))
	}
	if NotZeroString(d, "authorization_encryption_alg") {
		newClient.SetAuthorizationEncryptionAlg(mapInterfaceToType[authlete3.JweAlg](d.Get("authorization_encryption_alg")))
	}
	if NotZeroString(d, "authorization_encryption_enc") {
		newClient.SetAuthorizationEncryptionEnc(mapInterfaceToType[authlete3.JweEnc](d.Get("authorization_encryption_enc")))
	}
	if NotZeroString(d, "bc_request_sign_alg") {
		newClient.SetBcRequestSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("bc_request_sign_alg")))
	}
	newClient.SetAttributes(mapInterfaceListToStructList[authlete3.Pair](d.Get("attributes").(*schema.Set).List()))

	newClient.SetClientUris(mapTaggedValuesToDTOV3(d.Get("client_uris").(*schema.Set).List()))
	newClient.SetDpopRequired(d.Get("dpop_required").(bool))

	newClient.SetContacts(mapSetToString(d.Get("contacts").(*schema.Set).List()))
	if NotZeroString(d, "client_name") {
		newClient.SetClientName(d.Get("client_name").(string))
	}

	if NotZeroString(d, "logo_uri") {
		newClient.SetLogoUri(d.Get("logo_uri").(string))
	}

	if NotZeroString(d, "client_uri") {
		newClient.SetClientUri(d.Get("client_uri").(string))
	}
	newClient.SetPkceRequired(d.Get("pkce_required").(bool))
	newClient.SetPkceS256Required(d.Get("pkce_s256_required").(bool))
	if NotZeroString(d, "policy_uri") {
		newClient.SetPolicyUri(d.Get("policy_uri").(string))
	}

	if NotZeroString(d, "tos_uri") {
		newClient.SetTosUri(d.Get("tos_uri").(string))
	}

	if NotZeroString(d, "jwks_uri") {
		newClient.SetJwksUri(d.Get("jwks_uri").(string))
	}
	if NotZeroString(d, "jwks") {
		newClient.SetJwks(d.Get("jwks").(string))
	} else if NotZeroArray(d, "jwk") {
		var jwk string
		jwk, _ = mapJWKS(d.Get("jwk").(*schema.Set).List(), diags)
		newClient.SetJwks(jwk)
	}
	if NotZeroString(d, "derived_sector_identifier") {
		newClient.SetDerivedSectorIdentifier(d.Get("derived_sector_identifier").(string))
	}
	if NotZeroString(d, "sector_identifier_uri") {
		newClient.SetSectorIdentifierUri(d.Get("sector_identifier_uri").(string))
	}

	newClient.SetDefaultMaxAge(int32(d.Get("default_max_age").(int)))
	newClient.SetDefaultAcrs(mapSetToString(d.Get("default_acrs").(*schema.Set).List()))
	newClient.SetAuthTimeRequired(d.Get("auth_time_required").(bool))
	if NotZeroString(d, "login_uri") {
		newClient.SetLoginUri(d.Get("login_uri").(string))
	}
	newClient.SetRequestUris(mapSetToString(d.Get("request_uris").(*schema.Set).List()))
	if NotZeroString(d, "description") {
		newClient.SetDescription(d.Get("description").(string))
	}

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
	if NotZeroString(d, "bc_delivery_mode") {
		newClient.SetBcDeliveryMode(d.Get("bc_delivery_mode").(string))
	}
	if NotZeroString(d, "bc_notification_endpoint") {
		newClient.SetBcNotificationEndpoint(d.Get("bc_notification_endpoint").(string))
	}
	newClient.SetBcUserCodeRequired(d.Get("bc_user_code_required").(bool))
	newClient.SetDynamicallyRegistered(d.Get("dynamically_registered").(bool))
	if NotZeroString(d, "registration_access_token_hash") {
		newClient.SetRegistrationAccessTokenHash(d.Get("registration_access_token_hash").(string))
	}
	newClient.SetAuthorizationDetailsTypes(mapSetToString(d.Get("authorization_details_types").(*schema.Set).List()))
	newClient.SetParRequired(d.Get("par_required").(bool))
	newClient.SetRequestObjectRequired(d.Get("request_object_required").(bool))
	if NotZeroString(d, "custom_metadata") {
		newClient.SetCustomMetadata(d.Get("custom_metadata").(string))
	}
	newClient.SetFrontChannelRequestObjectEncryptionRequired(d.Get("front_channel_request_object_encryption_required").(bool))
	newClient.SetRequestObjectEncryptionAlgMatchRequired(d.Get("request_object_encryption_alg_match_required").(bool))
	newClient.SetRequestObjectEncryptionEncMatchRequired(d.Get("request_object_encryption_enc_match_required").(bool))
	newClient.SetDigestAlgorithm(d.Get("digest_algorithm").(string))
	newClient.SetSingleAccessTokenPerSubject(d.Get("single_access_token_per_subject").(bool))

	return *newClient
}

func setDataToClient(d *schema.ResourceData, diags diag.Diagnostics, client authlete3.Client) {

	if d.HasChange("client_id_alias") {
		if NotZeroString(d, "client_id_alias") {
			client.SetClientIdAlias(d.Get("client_id_alias").(string))
		} else {
			client.SetClientIdAlias(strconv.FormatInt(int64(d.Get("client_id").(int)), 10))
		}
	}
	if d.HasChange("client_id_alias_enabled") {
		client.SetClientIdAliasEnabled(d.Get("client_id_alias_enabled").(bool))
	}
	if d.HasChange("client_type") {
		if NotZeroString(d, "client_type") {
			client.SetClientType(authlete3.ClientType(d.Get("client_type").(string)))
		} else {
			client.ClientType = nil
		}
	}
	if d.HasChange("redirect_uris") {
		client.SetRedirectUris(mapSetToString(d.Get("redirect_uris").(*schema.Set).List()))
	}
	if d.HasChange("response_types") {
		client.SetResponseTypes(mapListToDTO[authlete3.ResponseType](d.Get("response_types").(*schema.Set).List()))
	}
	if d.HasChange("grant_types") {
		client.SetGrantTypes(mapSetToDTO[authlete3.GrantType](d.Get("grant_types").(*schema.Set)))
	}
	if d.HasChange("application_type") {
		if NotZeroString(d, "application_type") {
			client.SetApplicationType(mapInterfaceToType[authlete3.ApplicationType](d.Get("application_type")))
		} else {
			client.SetApplicationTypeNil()
		}
	}
	if d.HasChange("contacts") {
		client.SetContacts(mapSetToString(d.Get("contacts").(*schema.Set).List()))
	}
	if d.HasChange("client_name") {
		if NotZeroString(d, "client_name") {
			client.SetClientName(d.Get("client_name").(string))
		} else {
			client.ClientName = nil
		}
	}
	if d.HasChange("client_names") {
		client.SetClientNames(mapTaggedValuesToDTOV3(d.Get("client_names").(*schema.Set).List()))
	}
	if d.HasChange("logo_uri") {
		if NotZeroString(d, "logo_uri") {
			client.SetLogoUri(d.Get("logo_uri").(string))
		} else {
			client.LogoUri = nil
		}
	}
	if d.HasChange("logo_uris") {
		client.SetLogoUris(mapTaggedValuesToDTOV3(d.Get("logo_uris").(*schema.Set).List()))
	}
	if d.HasChange("client_uri") {
		if NotZeroString(d, "client_uri") {
			client.SetClientUri(d.Get("client_uri").(string))
		} else {
			client.ClientUri = nil
		}
	}
	if d.HasChange("client_uris") {
		client.SetClientUris(mapTaggedValuesToDTOV3(d.Get("client_uris").(*schema.Set).List()))
	}
	if d.HasChange("policy_uri") {
		if NotZeroString(d, "policy_uri") {
			client.SetPolicyUri(d.Get("policy_uri").(string))
		} else {
			client.PolicyUri = nil
		}
	}
	if d.HasChange("policy_uris") {
		client.SetPolicyUris(mapTaggedValuesToDTOV3(d.Get("policy_uris").(*schema.Set).List()))
	}
	if d.HasChange("tos_uri") {
		if NotZeroString(d, "tos_uri") {
			client.SetTosUri(d.Get("tos_uri").(string))
		} else {
			client.TosUri = nil
		}
	}
	if d.HasChange("tos_uris") {
		client.SetTosUris(mapTaggedValuesToDTOV3(d.Get("tos_uris").(*schema.Set).List()))
	}
	if d.HasChange("jwks_uri") {
		if NotZeroString(d, "jwks_uri") {
			client.SetJwksUri(d.Get("jwks_uri").(string))
		} else {
			client.JwksUri = nil
		}
	}
	if d.HasChanges("jwks", "jwk") {
		if NotZeroString(d, "jwks") {
			client.SetJwks(d.Get("jwks").(string))
		} else if NotZeroArray(d, "jwk") {
			var jwk string
			jwk, _ = updateJWKS(d.Get("jwk").(*schema.Set).List(), client.GetJwks(), diags)
			client.SetJwks(jwk)
		}
	}
	if d.HasChange("derived_sector_identifier") {
		if NotZeroString(d, "derived_sector_identifier") {
			client.SetDerivedSectorIdentifier(d.Get("derived_sector_identifier").(string))
		} else {
			client.DerivedSectorIdentifier = nil
		}
	}
	if d.HasChange("sector_identifier_uri") {
		if NotZeroString(d, "sector_identifier_uri") {
			client.SetSectorIdentifierUri(d.Get("sector_identifier_uri").(string))
		} else {
			client.SectorIdentifierUri = nil
		}
	}
	if d.HasChange("subject_type") {
		if NotZeroString(d, "subject_type") {
			client.SetSubjectType(mapInterfaceToType[authlete3.SubjectType](d.Get("subject_type")))
		} else {
			client.SubjectType = nil
		}
	}
	if d.HasChange("id_token_sign_alg") {
		if NotZeroString(d, "id_token_sign_alg") {
			client.SetIdTokenSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("id_token_sign_alg")))
		} else {
			client.IdTokenSignAlg = nil
		}
	}
	if d.HasChange("id_token_encryption_alg") {
		if NotZeroString(d, "id_token_encryption_alg") {
			client.SetIdTokenEncryptionAlg(mapInterfaceToType[authlete3.JweAlg](d.Get("id_token_encryption_alg")))
		} else {
			client.IdTokenEncryptionAlg = nil
		}
	}
	if d.HasChange("id_token_encryption_enc") {
		if NotZeroString(d, "id_token_encryption_enc") {
			client.SetIdTokenEncryptionEnc(mapInterfaceToType[authlete3.JweEnc](d.Get("id_token_encryption_enc")))
		} else {
			client.IdTokenEncryptionEnc = nil
		}
	}
	if d.HasChange("user_info_sign_alg") {
		if NotZeroString(d, "user_info_sign_alg") {
			client.SetUserInfoSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("user_info_sign_alg")))
		} else {
			client.UserInfoSignAlg = nil
		}
	}
	if d.HasChange("user_info_encryption_alg") {
		if NotZeroString(d, "user_info_encryption_alg") {
			client.SetUserInfoEncryptionAlg(mapInterfaceToType[authlete3.JweAlg](d.Get("user_info_encryption_alg")))
		} else {
			client.UserInfoEncryptionAlg = nil
		}
	}
	if d.HasChange("user_info_encryption_enc") {
		if NotZeroString(d, "user_info_encryption_enc") {
			client.SetUserInfoEncryptionEnc(mapInterfaceToType[authlete3.JweEnc](d.Get("user_info_encryption_enc")))
		} else {
			client.UserInfoEncryptionEnc = nil
		}
	}
	if d.HasChange("request_sign_alg") {
		if NotZeroString(d, "request_sign_alg") {
			client.SetRequestSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("request_sign_alg")))
		} else {
			client.RequestSignAlg = nil
		}
	}
	if d.HasChange("request_encryption_alg") {
		if NotZeroString(d, "request_encryption_alg") {
			client.SetRequestEncryptionAlg(mapInterfaceToType[authlete3.JweAlg](d.Get("request_encryption_alg")))
		} else {
			client.RequestEncryptionAlg = nil
		}
	}
	if d.HasChange("request_encryption_enc") {
		if NotZeroString(d, "request_encryption_enc") {
			client.SetRequestEncryptionEnc(mapInterfaceToType[authlete3.JweEnc](d.Get("request_encryption_enc")))
		} else {
			client.RequestEncryptionEnc = nil
		}
	}
	if d.HasChange("token_auth_method") {
		if NotZeroString(d, "token_auth_method") {
			client.SetTokenAuthMethod(mapInterfaceToType[authlete3.ClientAuthMethod](d.Get("token_auth_method")))
		} else {
			client.TokenAuthMethod = nil
		}
	}
	if d.HasChange("token_auth_sign_alg") {
		if NotZeroString(d, "token_auth_sign_alg") {
			client.SetTokenAuthSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("token_auth_sign_alg")))
		} else {
			client.TokenAuthSignAlg = nil
		}
	}
	if d.HasChange("default_max_age") {
		client.SetDefaultMaxAge(int32(d.Get("default_max_age").(int)))
	}
	if d.HasChange("default_acrs") {
		client.SetDefaultAcrs(mapSetToString(d.Get("default_acrs").(*schema.Set).List()))
	}
	if d.HasChange("auth_time_required") {
		client.SetAuthTimeRequired(d.Get("auth_time_required").(bool))
	}
	if d.HasChange("login_uri") {
		if NotZeroString(d, "login_uri") {
			client.SetLoginUri(d.Get("login_uri").(string))
		} else {
			client.LogoUri = nil
		}
	}
	if d.HasChange("request_uris") {
		client.SetRequestUris(mapSetToString(d.Get("request_uris").(*schema.Set).List()))
	}
	if d.HasChange("description") {
		if NotZeroString(d, "description") {
			client.SetDescription(d.Get("description").(string))
		} else {
			client.Description = nil
		}
	}
	if d.HasChange("descriptions") {
		client.SetDescriptions(mapTaggedValuesToDTOV3(d.Get("descriptions").(*schema.Set).List()))
	}
	if d.HasChanges("requestable_scopes_enabled", "requestable_scopes",
		"access_token_duration", "refresh_token_duration") {
		ext := authlete3.NewClientExtension()
		ext.SetRequestableScopesEnabled(d.Get("requestable_scopes_enabled").(bool))
		ext.SetRequestableScopes(mapSetToString(d.Get("requestable_scopes").(*schema.Set).List()))
		ext.SetAccessTokenDuration(int64(d.Get("access_token_duration").(int)))
		ext.SetRefreshTokenDuration(int64(d.Get("refresh_token_duration").(int)))
		client.SetExtension(*ext)
	}
	if d.HasChange("tls_client_auth_subject_dn") {
		if NotZeroString(d, "tls_client_auth_subject_dn") {
			client.SetTlsClientAuthSubjectDn(d.Get("tls_client_auth_subject_dn").(string))
		} else {
			client.TlsClientAuthSubjectDn = nil
		}
	}
	if d.HasChange("tls_client_auth_san_dns") {
		if NotZeroString(d, "tls_client_auth_san_dns") {
			client.SetTlsClientAuthSanDns(d.Get("tls_client_auth_san_dns").(string))
		} else {
			client.TlsClientAuthSanDns = nil
		}
	}
	if d.HasChange("tls_client_auth_san_uri") {
		if NotZeroString(d, "tls_client_auth_san_uri") {
			client.SetTlsClientAuthSanUri(d.Get("tls_client_auth_san_uri").(string))
		} else {
			client.TlsClientAuthSanUri = nil
		}
	}
	if d.HasChange("tls_client_auth_san_ip") {
		if NotZeroString(d, "tls_client_auth_san_ip") {
			client.SetTlsClientAuthSanIp(d.Get("tls_client_auth_san_ip").(string))
		} else {
			client.TlsClientAuthSanIp = nil
		}
	}
	if d.HasChange("tls_client_auth_san_email") {
		if NotZeroString(d, "tls_client_auth_san_email") {
			client.SetTlsClientAuthSanEmail(d.Get("tls_client_auth_san_email").(string))
		} else {
			client.TlsClientAuthSanEmail = nil
		}
	}
	if d.HasChange("tls_client_certificate_bound_access_tokens") {
		client.SetTlsClientCertificateBoundAccessTokens(d.Get("tls_client_certificate_bound_access_tokens").(bool))
	}
	if d.HasChange("self_signed_certificate_key_id") {
		if NotZeroString(d, "self_signed_certificate_key_id") {
			client.SetSelfSignedCertificateKeyId(d.Get("self_signed_certificate_key_id").(string))
		} else {
			client.SelfSignedCertificateKeyId = nil
		}
	}
	if d.HasChange("software_id") {
		if NotZeroString(d, "software_id") {
			client.SetSoftwareId(d.Get("software_id").(string))
		} else {
			client.SoftwareId = nil
		}
	}
	if d.HasChange("software_version") {
		if NotZeroString(d, "software_version") {
			client.SetSoftwareVersion(d.Get("software_version").(string))
		} else {
			client.SoftwareVersion = nil
		}
	}
	if d.HasChange("authorization_sign_alg") {
		if NotZeroString(d, "authorization_sign_alg") {
			client.SetAuthorizationSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("authorization_sign_alg")))
		} else {
			client.AuthorizationSignAlg = nil
		}
	}
	if d.HasChange("authorization_encryption_alg") {
		if NotZeroString(d, "authorization_encryption_alg") {
			client.SetAuthorizationEncryptionAlg(mapInterfaceToType[authlete3.JweAlg](d.Get("authorization_encryption_alg")))
		} else {
			client.AuthorizationEncryptionAlg = nil
		}
	}
	if d.HasChange("authorization_encryption_enc") {
		if NotZeroString(d, "authorization_encryption_enc") {
			client.SetAuthorizationEncryptionEnc(mapInterfaceToType[authlete3.JweEnc](d.Get("authorization_encryption_enc")))
		} else {
			client.AuthorizationEncryptionEnc = nil
		}
	}
	if d.HasChange("bc_delivery_mode") {
		if NotZeroString(d, "bc_delivery_mode") {
			client.SetBcDeliveryMode(d.Get("bc_delivery_mode").(string))
		} else {
			client.BcDeliveryMode = nil
		}
	}
	if d.HasChange("bc_notification_endpoint") {
		if NotZeroString(d, "bc_notification_endpoint") {
			client.SetBcNotificationEndpoint(d.Get("bc_notification_endpoint").(string))
		} else {
			client.BcNotificationEndpoint = nil
		}
	}
	if d.HasChange("bc_request_sign_alg") {
		if NotZeroString(d, "bc_request_sign_alg") {
			client.SetBcRequestSignAlg(mapInterfaceToType[authlete3.JwsAlg](d.Get("bc_request_sign_alg")))
		} else {
			client.BcRequestSignAlg = nil
		}
	}
	if d.HasChange("bc_user_code_required") {
		client.SetBcUserCodeRequired(d.Get("bc_user_code_required").(bool))
	}
	if d.HasChange("dynamically_registered") {
		client.SetDynamicallyRegistered(d.Get("dynamically_registered").(bool))
	}
	if d.HasChange("registration_access_token_hash") {
		if NotZeroString(d, "registration_access_token_hash") {
			client.SetRegistrationAccessTokenHash(d.Get("registration_access_token_hash").(string))
		} else {
			client.RegistrationAccessTokenHash = nil
		}
	}
	if d.HasChange("authorization_details_types") {
		client.SetAuthorizationDetailsTypes(mapSetToString(d.Get("authorization_details_types").(*schema.Set).List()))
	}
	if d.HasChange("par_required") {
		client.SetParRequired(d.Get("par_required").(bool))
	}
	if d.HasChange("request_object_required") {
		client.SetRequestObjectRequired(d.Get("request_object_required").(bool))
	}
	if d.HasChange("attributes") {
		client.SetAttributes(
			mapInterfaceListToStructList[authlete3.Pair](d.Get("attributes").(*schema.Set).List()))
	}
	if d.HasChange("custom_metadata") {
		if NotZeroString(d, "custom_metadata") {
			client.SetCustomMetadata(d.Get("custom_metadata").(string))
		} else {
			client.SetCustomMetadata("")
		}
	}
	if d.HasChange("front_channel_request_object_encryption_required") {
		client.SetFrontChannelRequestObjectEncryptionRequired(d.Get("front_channel_request_object_encryption_required").(bool))
	}
	if d.HasChange("request_object_encryption_alg_match_required") {
		client.SetRequestObjectEncryptionAlgMatchRequired(d.Get("request_object_encryption_alg_match_required").(bool))
	}
	if d.HasChange("request_object_encryption_enc_match_required") {
		client.SetRequestObjectEncryptionEncMatchRequired(d.Get("request_object_encryption_enc_match_required").(bool))
	}

	if d.HasChange("digest_algorithm") {
		client.SetDigestAlgorithm(d.Get("digest_algorithm").(string))
	}

	if d.HasChange("single_access_token_per_subject") {
		client.SetSingleAccessTokenPerSubject(d.Get("single_access_token_per_subject").(bool))
	}
	if d.HasChange("pkce_required") {
		client.SetPkceRequired(d.Get("pkce_required").(bool))
	}
	if d.HasChange("pkce_s256_required") {
		client.SetPkceS256Required(d.Get("pkce_s256_required").(bool))
	}

	if d.HasChange("dpop_required") {
		client.SetDpopRequired(d.Get("dpop_required").(bool))
	}
}

func updateResourceFromClient(d *schema.ResourceData, client authlete3.Client) {
	_ = d.Set("client_id", client.GetClientId())
	_ = d.Set("client_secret", client.GetClientSecret())
	_ = d.Set("client_id_alias", client.GetClientIdAlias())

	c := client
	_ = d.Set("client_type", c.GetClientType())
	_ = d.Set("grant_types", c.GetGrantTypes())
	_ = d.Set("response_types", c.GetResponseTypes())
	_ = d.Set("application_type", c.GetApplicationType())
	_ = d.Set("logo_uris", mapTaggedValuesFromDTOV3(c.GetLogoUris()))
	_ = d.Set("client_names", mapTaggedValuesFromDTOV3(c.GetClientNames()))
	_ = d.Set("client_uris", mapTaggedValuesFromDTOV3(c.GetClientUris()))
	_ = d.Set("policy_uris", mapTaggedValuesFromDTOV3(c.GetPolicyUris()))
	_ = d.Set("tos_uris", mapTaggedValuesFromDTOV3(c.GetTosUris()))
	_ = d.Set("subject_type", c.GetSubjectType())
	_ = d.Set("id_token_sign_alg", c.GetIdTokenSignAlg())
	_ = d.Set("id_token_encryption_alg", c.GetIdTokenEncryptionAlg())
	_ = d.Set("id_token_encryption_enc", c.GetIdTokenEncryptionEnc())
	_ = d.Set("user_info_sign_alg", c.GetUserInfoSignAlg())
	_ = d.Set("user_info_encryption_alg", c.GetUserInfoEncryptionAlg())
	_ = d.Set("user_info_encryption_enc", c.GetUserInfoEncryptionEnc())
	_ = d.Set("request_sign_alg", c.GetRequestSignAlg())
	_ = d.Set("request_encryption_alg", c.GetRequestEncryptionAlg())
	_ = d.Set("request_encryption_enc", c.GetRequestEncryptionEnc())
	_ = d.Set("token_auth_method", c.GetTokenAuthMethod())
	_ = d.Set("token_auth_sign_alg", c.GetTokenAuthSignAlg())
	_ = d.Set("descriptions", mapTaggedValuesFromDTOV3(c.GetDescriptions()))
	_ = d.Set("authorization_sign_alg", c.GetAuthorizationSignAlg())
	_ = d.Set("authorization_encryption_alg", c.GetAuthorizationEncryptionAlg())
	_ = d.Set("authorization_encryption_enc", c.GetAuthorizationEncryptionEnc())
	_ = d.Set("bc_request_sign_alg", c.GetBcRequestSignAlg())
	_ = d.Set("attributes", mapAttributesFromDTOV3(c.GetAttributes()))
	clientExtension := (client).GetExtension()
	_ = d.Set("requestable_scopes_enabled", clientExtension.GetRequestableScopesEnabled())
	_ = d.Set("requestable_scopes", clientExtension.GetRequestableScopes())
	_ = d.Set("access_token_duration", clientExtension.GetAccessTokenDuration())
	_ = d.Set("refresh_token_duration", clientExtension.GetRefreshTokenDuration())

	_ = d.Set("redirect_uris", client.GetRedirectUris())
	_ = d.Set("contacts", client.GetContacts())
	_ = d.Set("client_name", client.GetClientName())
	_ = d.Set("logo_uri", client.GetLogoUri())
	_ = d.Set("client_uri", client.GetClientUri())
	_ = d.Set("policy_uri", client.GetPolicyUri())
	_ = d.Set("tos_uri", client.GetTosUri())
	_ = d.Set("jwks_uri", client.GetJwksUri())
	_ = d.Set("jwks", nil)

	jwk, _ := mapJWKFromDTO(d.Get("jwk").(*schema.Set).List(), client.GetJwks())

	_ = d.Set("jwk", jwk)
	_ = d.Set("pkce_required", client.GetPkceRequired())
	_ = d.Set("pkce_s256_required", client.GetPkceS256Required())
	_ = d.Set("derived_sector_identifier", client.GetDerivedSectorIdentifier())
	_ = d.Set("sector_identifier_uri", client.GetSectorIdentifierUri())
	_ = d.Set("default_max_age", client.GetDefaultMaxAge())
	_ = d.Set("default_acrs", client.GetDefaultAcrs())
	_ = d.Set("auth_time_required", client.GetAuthTimeRequired())
	_ = d.Set("login_uri", client.GetLoginUri())
	_ = d.Set("request_uris", client.GetRequestUris())
	_ = d.Set("description", client.GetDescription())
	_ = d.Set("created_at", client.GetCreatedAt())
	_ = d.Set("modified_at", client.GetModifiedAt())
	_ = d.Set("tls_client_auth_subject_dn", client.GetTlsClientAuthSubjectDn())
	_ = d.Set("tls_client_auth_san_dns", client.GetTlsClientAuthSanDns())
	_ = d.Set("tls_client_auth_san_uri", client.GetTlsClientAuthSanUri())
	_ = d.Set("tls_client_auth_san_ip", client.GetTlsClientAuthSanIp())
	_ = d.Set("tls_client_auth_san_email", client.GetTlsClientAuthSanEmail())
	_ = d.Set("tls_client_certificate_bound_access_tokens", client.GetTlsClientCertificateBoundAccessTokens())
	_ = d.Set("self_signed_certificate_key_id", client.GetSelfSignedCertificateKeyId())
	_ = d.Set("software_id", client.GetSoftwareId())
	_ = d.Set("software_version", client.GetSoftwareVersion())
	_ = d.Set("bc_delivery_mode", client.GetBcDeliveryMode())
	_ = d.Set("bc_notification_endpoint", client.GetBcNotificationEndpoint())
	_ = d.Set("bc_user_code_required", client.GetBcUserCodeRequired())
	_ = d.Set("dynamically_registered", client.GetDynamicallyRegistered())
	_ = d.Set("registration_access_token_hash", client.GetRegistrationAccessTokenHash())
	_ = d.Set("authorization_details_types", client.GetAuthorizationDetailsTypes())
	_ = d.Set("par_required", client.GetParRequired())
	_ = d.Set("request_object_required", client.GetRequestObjectRequired())
	_ = d.Set("custom_metadata", client.GetCustomMetadata())
	_ = d.Set("front_channel_request_object_encryption_required", client.GetFrontChannelRequestObjectEncryptionRequired())
	_ = d.Set("request_object_encryption_alg_match_required", client.GetRequestObjectEncryptionAlgMatchRequired())
	_ = d.Set("request_object_encryption_enc_match_required", client.GetRequestObjectEncryptionAlgMatchRequired())
	_ = d.Set("digest_algorithm", client.GetDigestAlgorithm())
	_ = d.Set("single_access_token_per_subject", client.GetSingleAccessTokenPerSubject())
	_ = d.Set("dpop_required", client.GetDpopRequired())
}

func getClientIdentifierForV3(d *schema.ResourceData) string {
	clientIdentifier := d.Get("client_identifier").(string)
	if clientIdentifier != "" {
		return clientIdentifier
	}
	return d.Id()
}
