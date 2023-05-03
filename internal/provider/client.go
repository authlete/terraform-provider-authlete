package provider

import (
	"context"
	"fmt"
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
			"service_api_key":    {Type: schema.TypeString, Required: false, Optional: true},
			"service_api_secret": {Type: schema.TypeString, Required: false, Optional: true, Sensitive: true},
			"developer":          {Type: schema.TypeString, Required: true},
			"client_id":          {Type: schema.TypeInt, Required: false, Optional: true, Computed: true},
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

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: apiKey,
		Password: apiSecret,
	})

	newClientDto := dataToClient(d, diags)

	newOauthClient, _, err := client.authleteClient.ClientManagementApi.ClientCreateApi(auth).Client(*newClientDto).Execute()

	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Client created")
	if d.Get("client_secret").(string) != "" {
		cliSecretUpdateRequest := authlete.ClientSecretUpdateRequest{ClientSecret: d.Get("client_secret").(string)}
		updateSecretRequest := client.authleteClient.ClientManagementApi.ClientSecretUpdateApi(auth,
			strconv.FormatInt(newOauthClient.GetClientId(), 10))

		_, _, err := updateSecretRequest.ClientSecretUpdateRequest(cliSecretUpdateRequest).Execute()
		if err != nil {
			return diag.FromErr(err)
		}
		newOauthClient.SetClientSecret(d.Get("client_secret").(string))
	}

	updateResourceFromClient(d, newOauthClient)
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

	apiKey := client.apiKey
	apiSecret := client.apiSecret

	if d.Get("service_api_key") != "" && client.apiKey != d.Get("service_api_key") {
		apiKey = d.Get("service_api_key").(string)
		apiSecret = d.Get("service_api_secret").(string)
	}

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: apiKey,
		Password: apiSecret,
	})

	existingClient, _, getErr := client.authleteClient.ClientManagementApi.ClientGetApi(auth, d.Id()).Execute()

	if getErr != nil {
		return diag.FromErr(getErr)
	}

	if d.HasChange("developer") {
		existingClient.SetDeveloper(d.Get("developer").(string))
	}
	if d.HasChange("client_id_alias") {
		if NotZeroString(d, "client_id_alias") {
			existingClient.SetClientIdAlias(d.Get("client_id_alias").(string))
		} else {
			existingClient.ClientIdAlias = nil
		}
	}
	if d.HasChange("client_id_alias_enabled") {
		existingClient.SetClientIdAliasEnabled(d.Get("client_id_alias_enabled").(bool))
	}
	if d.HasChange("client_type") {
		if NotZeroString(d, "client_type") {
			existingClient.SetClientType(authlete.ClientType(d.Get("client_type").(string)))
		} else {
			existingClient.ClientType = nil
		}
	}
	if d.HasChange("redirect_uris") {
		existingClient.SetRedirectUris(mapSetToString(d.Get("redirect_uris").(*schema.Set).List()))
	}
	if d.HasChange("response_types") {
		existingClient.SetResponseTypes(mapResponseTypesToDTO(d.Get("response_types").([]interface{})))
	}
	if d.HasChange("grant_types") {
		existingClient.SetGrantTypes(mapGrantTypesToDTO(d.Get("grant_types").(*schema.Set)))
	}
	if d.HasChange("application_type") {
		if NotZeroString(d, "application_type") {
			existingClient.SetApplicationType(mapApplicationTypeToDto(d.Get("application_type")))
		} else {
			existingClient.SetApplicationTypeNil()
		}
	}
	if d.HasChange("contacts") {
		existingClient.SetContacts(mapSetToString(d.Get("contacts").(*schema.Set).List()))
	}
	if d.HasChange("client_name") {
		if NotZeroString(d, "client_name") {
			existingClient.SetClientName(d.Get("client_name").(string))
		} else {
			existingClient.ClientName = nil
		}
	}
	if d.HasChange("client_names") {
		existingClient.SetClientNames(mapTaggedValuesToDTO(d.Get("client_names").(*schema.Set).List()))
	}
	if d.HasChange("logo_uri") {
		if NotZeroString(d, "logo_uri") {
			existingClient.SetLogoUri(d.Get("logo_uri").(string))
		} else {
			existingClient.LogoUri = nil
		}
	}
	if d.HasChange("logo_uris") {
		existingClient.SetLogoUris(mapTaggedValuesToDTO(d.Get("logo_uris").(*schema.Set).List()))
	}
	if d.HasChange("") {
		if NotZeroString(d, "client_uri") {
			existingClient.SetClientUri(d.Get("client_uri").(string))
		} else {
			existingClient.ClientUri = nil
		}
	}
	if d.HasChange("client_uris") {
		existingClient.SetClientUris(mapTaggedValuesToDTO(d.Get("client_uris").(*schema.Set).List()))
	}
	if d.HasChange("policy_uri") {
		if NotZeroString(d, "policy_uri") {
			existingClient.SetPolicyUri(d.Get("policy_uri").(string))
		} else {
			existingClient.PolicyUri = nil
		}
	}
	if d.HasChange("policy_uris") {
		existingClient.SetPolicyUris(mapTaggedValuesToDTO(d.Get("policy_uris").(*schema.Set).List()))
	}
	if d.HasChange("tos_uri") {
		if NotZeroString(d, "tos_uri") {
			existingClient.SetTosUri(d.Get("tos_uri").(string))
		} else {
			existingClient.TosUri = nil
		}
	}
	if d.HasChange("tos_uris") {
		existingClient.SetTosUris(mapTaggedValuesToDTO(d.Get("tos_uris").(*schema.Set).List()))
	}
	if d.HasChange("jwks_uri") {
		if NotZeroString(d, "jwks_uri") {
			existingClient.SetJwksUri(d.Get("jwks_uri").(string))
		} else {
			existingClient.JwksUri = nil
		}
	}
	if d.HasChanges("jwks", "jwk") {
		if NotZeroString(d, "jwks") {
			existingClient.SetJwks(d.Get("jwks").(string))
		} else if NotZeroArray(d, "jwk") {
			var jwk string
			jwk, diags = updateJWKS(d.Get("jwk").(*schema.Set).List(), existingClient.GetJwks(), diags)
			existingClient.SetJwks(jwk)
		}
	}
	if d.HasChange("derived_sector_identifier") {
		if NotZeroString(d, "derived_sector_identifier") {
			existingClient.SetDerivedSectorIdentifier(d.Get("derived_sector_identifier").(string))
		} else {
			existingClient.DerivedSectorIdentifier = nil
		}
	}
	if d.HasChange("sector_identifier_uri") {
		if NotZeroString(d, "sector_identifier_uri") {
			existingClient.SetSectorIdentifierUri(d.Get("sector_identifier_uri").(string))
		} else {
			existingClient.SectorIdentifierUri = nil
		}
	}
	if d.HasChange("subject_type") {
		if NotZeroString(d, "subject_type") {
			existingClient.SetSubjectType(mapSubjectTypeToDto(d.Get("subject_type")))
		} else {
			existingClient.SubjectType = nil
		}
	}
	if d.HasChange("id_token_sign_alg") {
		if NotZeroString(d, "id_token_sign_alg") {
			existingClient.SetIdTokenSignAlg(mapJWSAlg(d.Get("id_token_sign_alg")))
		} else {
			existingClient.IdTokenSignAlg = nil
		}
	}
	if d.HasChange("id_token_encryption_alg") {
		if NotZeroString(d, "id_token_encryption_alg") {
			existingClient.SetIdTokenEncryptionAlg(mapJWEAlg(d.Get("id_token_encryption_alg")))
		} else {
			existingClient.IdTokenEncryptionAlg = nil
		}
	}
	if d.HasChange("id_token_encryption_enc") {
		if NotZeroString(d, "id_token_encryption_enc") {
			existingClient.SetIdTokenEncryptionEnc(mapJWEEnc(d.Get("id_token_encryption_enc")))
		} else {
			existingClient.IdTokenEncryptionEnc = nil
		}
	}
	if d.HasChange("user_info_sign_alg") {
		if NotZeroString(d, "user_info_sign_alg") {
			existingClient.SetUserInfoSignAlg(mapJWSAlg(d.Get("user_info_sign_alg")))
		} else {
			existingClient.UserInfoSignAlg = nil
		}
	}
	if d.HasChange("user_info_encryption_alg") {
		if NotZeroString(d, "user_info_encryption_alg") {
			existingClient.SetUserInfoEncryptionAlg(mapJWEAlg(d.Get("user_info_encryption_alg")))
		} else {
			existingClient.UserInfoEncryptionAlg = nil
		}
	}
	if d.HasChange("user_info_encryption_enc") {
		if NotZeroString(d, "user_info_encryption_enc") {
			existingClient.SetUserInfoEncryptionEnc(mapJWEEnc(d.Get("user_info_encryption_enc")))
		} else {
			existingClient.UserInfoEncryptionEnc = nil
		}
	}
	if d.HasChange("request_sign_alg") {
		if NotZeroString(d, "request_sign_alg") {
			existingClient.SetRequestSignAlg(mapJWSAlg(d.Get("request_sign_alg")))
		} else {
			existingClient.RequestSignAlg = nil
		}
	}
	if d.HasChange("request_encryption_alg") {
		if NotZeroString(d, "request_encryption_alg") {
			existingClient.SetRequestEncryptionAlg(mapJWEAlg(d.Get("request_encryption_alg")))
		} else {
			existingClient.RequestEncryptionAlg = nil
		}
	}
	if d.HasChange("request_encryption_enc") {
		if NotZeroString(d, "request_encryption_enc") {
			existingClient.SetRequestEncryptionEnc(mapJWEEnc(d.Get("request_encryption_enc")))
		} else {
			existingClient.RequestEncryptionEnc = nil
		}
	}
	if d.HasChange("token_auth_method") {
		if NotZeroString(d, "token_auth_method") {
			existingClient.SetTokenAuthMethod(mapClientAuthMethodToDto(d.Get("token_auth_method")))
		} else {
			existingClient.TokenAuthMethod = nil
		}
	}
	if d.HasChange("token_auth_sign_alg") {
		if NotZeroString(d, "token_auth_sign_alg") {
			existingClient.SetTokenAuthSignAlg(mapJWSAlg(d.Get("token_auth_sign_alg")))
		} else {
			existingClient.TokenAuthSignAlg = nil
		}
	}
	if d.HasChange("default_max_age") {
		existingClient.SetDefaultMaxAge(int32(d.Get("default_max_age").(int)))
	}
	if d.HasChange("default_acrs") {
		existingClient.SetDefaultAcrs(mapSetToString(d.Get("default_acrs").(*schema.Set).List()))
	}
	if d.HasChange("auth_time_required") {
		existingClient.SetAuthTimeRequired(d.Get("auth_time_required").(bool))
	}
	if d.HasChange("login_uri") {
		if NotZeroString(d, "login_uri") {
			existingClient.SetLoginUri(d.Get("login_uri").(string))
		} else {
			existingClient.LogoUri = nil
		}
	}
	if d.HasChange("request_uris") {
		existingClient.SetRequestUris(mapSetToString(d.Get("request_uris").(*schema.Set).List()))
	}
	if d.HasChange("description") {
		if NotZeroString(d, "description") {
			existingClient.SetDescription(d.Get("description").(string))
		} else {
			existingClient.Description = nil
		}
	}
	if d.HasChange("descriptions") {
		existingClient.SetDescriptions(mapTaggedValuesToDTO(d.Get("descriptions").(*schema.Set).List()))
	}
	if d.HasChanges("requestable_scopes_enabled", "requestable_scopes",
		"access_token_duration", "refresh_token_duration") {

		ext := authlete.NewClientExtension()
		ext.SetRequestableScopesEnabled(d.Get("requestable_scopes_enabled").(bool))
		ext.SetRequestableScopes(mapSetToString(d.Get("requestable_scopes").(*schema.Set).List()))
		ext.SetAccessTokenDuration(int64(d.Get("access_token_duration").(int)))
		ext.SetRefreshTokenDuration(int64(d.Get("refresh_token_duration").(int)))
		existingClient.SetExtension(*ext)
	}
	if d.HasChange("tls_client_auth_subject_dn") {
		if NotZeroString(d, "tls_client_auth_subject_dn") {
			existingClient.SetTlsClientAuthSubjectDn(d.Get("tls_client_auth_subject_dn").(string))
		} else {
			existingClient.TlsClientAuthSubjectDn = nil
		}
	}
	if d.HasChange("tls_client_auth_san_dns") {
		if NotZeroString(d, "tls_client_auth_san_dns") {
			existingClient.SetTlsClientAuthSanDns(d.Get("tls_client_auth_san_dns").(string))
		} else {
			existingClient.TlsClientAuthSanDns = nil
		}
	}
	if d.HasChange("tls_client_auth_san_uri") {
		if NotZeroString(d, "tls_client_auth_san_uri") {
			existingClient.SetTlsClientAuthSanUri(d.Get("tls_client_auth_san_uri").(string))
		} else {
			existingClient.TlsClientAuthSanUri = nil
		}
	}
	if d.HasChange("tls_client_auth_san_ip") {
		if NotZeroString(d, "tls_client_auth_san_ip") {
			existingClient.SetTlsClientAuthSanIp(d.Get("tls_client_auth_san_ip").(string))
		} else {
			existingClient.TlsClientAuthSanIp = nil
		}
	}
	if d.HasChange("tls_client_auth_san_email") {
		if NotZeroString(d, "tls_client_auth_san_email") {
			existingClient.SetTlsClientAuthSanEmail(d.Get("tls_client_auth_san_email").(string))
		} else {
			existingClient.TlsClientAuthSanEmail = nil
		}
	}
	if d.HasChange("tls_client_certificate_bound_access_tokens") {
		existingClient.SetTlsClientCertificateBoundAccessTokens(d.Get("tls_client_certificate_bound_access_tokens").(bool))
	}
	if d.HasChange("self_signed_certificate_key_id") {
		if NotZeroString(d, "self_signed_certificate_key_id") {
			existingClient.SetSelfSignedCertificateKeyId(d.Get("self_signed_certificate_key_id").(string))
		} else {
			existingClient.SelfSignedCertificateKeyId = nil
		}
	}
	if d.HasChange("software_id") {
		if NotZeroString(d, "software_id") {
			existingClient.SetSoftwareId(d.Get("software_id").(string))
		} else {
			existingClient.SoftwareId = nil
		}
	}
	if d.HasChange("software_version") {
		if NotZeroString(d, "software_version") {
			existingClient.SetSoftwareVersion(d.Get("software_version").(string))
		} else {
			existingClient.SoftwareVersion = nil
		}
	}
	if d.HasChange("authorization_sign_alg") {
		if NotZeroString(d, "authorization_sign_alg") {
			existingClient.SetAuthorizationSignAlg(mapJWSAlg(d.Get("authorization_sign_alg")))
		} else {
			existingClient.AuthorizationSignAlg = nil
		}
	}
	if d.HasChange("authorization_encryption_alg") {
		if NotZeroString(d, "authorization_encryption_alg") {
			existingClient.SetAuthorizationEncryptionAlg(mapJWEAlg(d.Get("authorization_encryption_alg")))
		} else {
			existingClient.AuthorizationEncryptionAlg = nil
		}
	}
	if d.HasChange("authorization_encryption_enc") {
		if NotZeroString(d, "authorization_encryption_enc") {
			existingClient.SetAuthorizationEncryptionEnc(mapJWEEnc(d.Get("authorization_encryption_enc")))
		} else {
			existingClient.AuthorizationEncryptionEnc = nil
		}
	}
	if d.HasChange("bc_delivery_mode") {
		if NotZeroString(d, "bc_delivery_mode") {
			existingClient.SetBcDeliveryMode(d.Get("bc_delivery_mode").(string))
		} else {
			existingClient.BcDeliveryMode = nil
		}
	}
	if d.HasChange("bc_notification_endpoint") {
		if NotZeroString(d, "bc_notification_endpoint") {
			existingClient.SetBcNotificationEndpoint(d.Get("bc_notification_endpoint").(string))
		} else {
			existingClient.BcNotificationEndpoint = nil
		}
	}
	if d.HasChange("bc_request_sign_alg") {
		if NotZeroString(d, "bc_request_sign_alg") {
			existingClient.SetBcRequestSignAlg(mapJWSAlg(d.Get("bc_request_sign_alg")))
		} else {
			existingClient.BcRequestSignAlg = nil
		}
	}
	if d.HasChange("bc_user_code_required") {
		existingClient.SetBcUserCodeRequired(d.Get("bc_user_code_required").(bool))
	}
	if d.HasChange("dynamically_registered") {
		existingClient.SetDynamicallyRegistered(d.Get("dynamically_registered").(bool))
	}
	if d.HasChange("registration_access_token_hash") {
		if NotZeroString(d, "registration_access_token_hash") {
			existingClient.SetRegistrationAccessTokenHash(d.Get("registration_access_token_hash").(string))
		} else {
			existingClient.RegistrationAccessTokenHash = nil
		}
	}
	if d.HasChange("authorization_details_types") {
		existingClient.SetAuthorizationDetailsTypes(mapSetToString(d.Get("authorization_details_types").(*schema.Set).List()))
	}
	if d.HasChange("par_required") {
		existingClient.SetParRequired(d.Get("par_required").(bool))
	}
	if d.HasChange("request_object_required") {
		existingClient.SetRequestObjectRequired(d.Get("request_object_required").(bool))
	}
	if d.HasChange("attributes") {
		existingClient.SetAttributes(mapAttributesToDTO(d.Get("attributes").([]interface{})))
	}
	if d.HasChange("custom_metadata") {
		if NotZeroString(d, "custom_metadata") {
			existingClient.SetCustomMetadata(d.Get("custom_metadata").(string))
		} else {
			existingClient.CustomMetadata = nil
		}
	}
	if d.HasChange("front_channel_request_object_encryption_required") {
		existingClient.SetFrontChannelRequestObjectEncryptionRequired(d.Get("front_channel_request_object_encryption_required").(bool))
	}
	if d.HasChange("request_object_encryption_alg_match_required") {
		existingClient.SetRequestObjectEncryptionAlgMatchRequired(d.Get("request_object_encryption_alg_match_required").(bool))
	}
	if d.HasChange("request_object_encryption_enc_match_required") {
		existingClient.SetRequestObjectEncryptionEncMatchRequired(d.Get("request_object_encryption_enc_match_required").(bool))
	}

	if d.HasChange("digest_algorithm") {
		existingClient.SetDigestAlgorithm(d.Get("digest_algorithm").(string))
	}

	if d.HasChange("single_access_token_per_subject") {
		existingClient.SetSingleAccessTokenPerSubject(d.Get("single_access_token_per_subject").(bool))
	}

	_, _, err := client.authleteClient.ClientManagementApi.ClientUpdateApi(auth, d.Id()).Client(*existingClient).Execute()

	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Client updated")

	if d.HasChange("client_secret") {
		if d.Get("client_secret").(string) != "" {
			cliSecretUpdateRequest := authlete.ClientSecretUpdateRequest{ClientSecret: d.Get("client_secret").(string)}
			updateSecretRequest := client.authleteClient.ClientManagementApi.ClientSecretUpdateApi(auth,
				d.Get("client_id").(string))

			_, _, err := updateSecretRequest.ClientSecretUpdateRequest(cliSecretUpdateRequest).Execute()

			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	updateResourceFromClient(d, existingClient)
	return diags
}

func clientDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	client := meta.(*apiClient)

	apiKey := client.apiKey
	apiSecret := client.apiSecret

	if d.Get("service_api_key") != "" && client.apiKey != d.Get("service_api_key") {
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

func dataToClient(d *schema.ResourceData, diags diag.Diagnostics) *authlete.Client {

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
	newClient.SetRedirectUris(mapSetToString(d.Get("redirect_uris").(*schema.Set).List()))
	newClient.SetResponseTypes(mapResponseTypesToDTO(d.Get("response_types").(*schema.Set).List()))
	newClient.SetGrantTypes(mapGrantTypesToDTO(d.Get("grant_types").(*schema.Set)))
	if NotZeroString(d, "application_type") {
		newClient.SetApplicationType(mapApplicationTypeToDto(d.Get("application_type")))
	}
	newClient.SetContacts(mapSetToString(d.Get("contacts").(*schema.Set).List()))
	if NotZeroString(d, "client_name") {
		newClient.SetClientName(d.Get("client_name").(string))
	}
	newClient.SetClientNames(mapTaggedValuesToDTO(d.Get("client_names").(*schema.Set).List()))
	if NotZeroString(d, "logo_uri") {
		newClient.SetLogoUri(d.Get("logo_uri").(string))
	}
	newClient.SetLogoUris(mapTaggedValuesToDTO(d.Get("logo_uris").(*schema.Set).List()))
	if NotZeroString(d, "client_uri") {
		newClient.SetClientUri(d.Get("client_uri").(string))
	}
	newClient.SetClientUris(mapTaggedValuesToDTO(d.Get("client_uris").(*schema.Set).List()))
	if NotZeroString(d, "policy_uri") {
		newClient.SetPolicyUri(d.Get("policy_uri").(string))
	}
	newClient.SetPolicyUris(mapTaggedValuesToDTO(d.Get("policy_uris").(*schema.Set).List()))
	if NotZeroString(d, "tos_uri") {
		newClient.SetTosUri(d.Get("tos_uri").(string))
	}
	newClient.SetTosUris(mapTaggedValuesToDTO(d.Get("tos_uris").(*schema.Set).List()))
	if NotZeroString(d, "jwks_uri") {
		newClient.SetJwksUri(d.Get("jwks_uri").(string))
	}
	if NotZeroString(d, "jwks") {
		newClient.SetJwks(d.Get("jwks").(string))
	} else if NotZeroArray(d, "jwk") {
		var jwk string
		jwk, diags = mapJWKS(d.Get("jwk").(*schema.Set).List(), diags)
		newClient.SetJwks(jwk)
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
	newClient.SetDefaultAcrs(mapSetToString(d.Get("default_acrs").(*schema.Set).List()))
	newClient.SetAuthTimeRequired(d.Get("auth_time_required").(bool))
	if NotZeroString(d, "login_uri") {
		newClient.SetLoginUri(d.Get("login_uri").(string))
	}
	newClient.SetRequestUris(mapSetToString(d.Get("request_uris").(*schema.Set).List()))
	if NotZeroString(d, "description") {
		newClient.SetDescription(d.Get("description").(string))
	}
	newClient.SetDescriptions(mapTaggedValuesToDTO(d.Get("descriptions").(*schema.Set).List()))

	ext := authlete.NewClientExtension()
	ext.SetRequestableScopesEnabled(d.Get("requestable_scopes_enabled").(bool))
	ext.SetRequestableScopes(mapSetToString(d.Get("requestable_scopes").(*schema.Set).List()))
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
	newClient.SetAuthorizationDetailsTypes(mapSetToString(d.Get("authorization_details_types").(*schema.Set).List()))
	newClient.SetParRequired(d.Get("par_required").(bool))
	newClient.SetRequestObjectRequired(d.Get("request_object_required").(bool))
	newClient.SetAttributes(mapAttributesToDTO(d.Get("attributes").(*schema.Set).List()))
	if NotZeroString(d, "custom_metadata") {
		newClient.SetCustomMetadata(d.Get("custom_metadata").(string))
	}
	newClient.SetFrontChannelRequestObjectEncryptionRequired(d.Get("front_channel_request_object_encryption_required").(bool))
	newClient.SetRequestObjectEncryptionAlgMatchRequired(d.Get("request_object_encryption_alg_match_required").(bool))
	newClient.SetRequestObjectEncryptionEncMatchRequired(d.Get("request_object_encryption_enc_match_required").(bool))
	newClient.SetDigestAlgorithm(d.Get("digest_algorithm").(string))
	newClient.SetSingleAccessTokenPerSubject(d.Get("single_access_token_per_subject").(bool))

	return newClient
}

func updateResourceFromClient(d *schema.ResourceData, client *authlete.Client) {
	_ = d.Set("developer", client.GetDeveloper())
	_ = d.Set("client_id", client.GetClientId())
	_ = d.Set("client_secret", client.GetClientSecret())
	_ = d.Set("client_id_alias", client.GetClientIdAlias())
	_ = d.Set("client_id_alias_enabled", client.GetClientIdAliasEnabled())
	_ = d.Set("client_type", client.GetClientType())
	_ = d.Set("redirect_uris", client.GetRedirectUris())
	_ = d.Set("grant_types", client.GetGrantTypes())
	_ = d.Set("response_types", client.GetResponseTypes())
	_ = d.Set("application_type", client.GetApplicationType())
	_ = d.Set("contacts", client.GetContacts())
	_ = d.Set("client_name", client.GetClientName())
	_ = d.Set("client_names", mapTaggedValuesFromDTO(client.GetClientNames()))
	_ = d.Set("logo_uri", client.GetLogoUri())
	_ = d.Set("logo_uris", mapTaggedValuesFromDTO(client.GetLogoUris()))
	_ = d.Set("client_uri", client.GetClientUri())
	_ = d.Set("client_uris", mapTaggedValuesFromDTO(client.GetClientUris()))
	_ = d.Set("policy_uri", client.GetPolicyUri())
	_ = d.Set("policy_uris", mapTaggedValuesFromDTO(client.GetPolicyUris()))
	_ = d.Set("tos_uri", client.GetTosUri())
	_ = d.Set("tos_uris", mapTaggedValuesFromDTO(client.GetTosUris()))
	_ = d.Set("jwks_uri", client.GetJwksUri())
	_ = d.Set("jwks", nil)

	jwk, _ := mapJWKFromDTO(d.Get("jwk").(*schema.Set).List(), client.GetJwks())

	_ = d.Set("jwk", jwk)

	_ = d.Set("derived_sector_identifier", client.GetDerivedSectorIdentifier())
	_ = d.Set("sector_identifier_uri", client.GetSectorIdentifierUri())
	_ = d.Set("subject_type", client.GetSubjectType())
	_ = d.Set("id_token_sign_alg", client.GetIdTokenSignAlg())
	_ = d.Set("id_token_encryption_alg", client.GetIdTokenEncryptionAlg())
	_ = d.Set("id_token_encryption_enc", client.GetIdTokenEncryptionEnc())
	_ = d.Set("user_info_sign_alg", client.GetUserInfoSignAlg())
	_ = d.Set("user_info_encryption_alg", client.GetUserInfoEncryptionAlg())
	_ = d.Set("user_info_encryption_enc", client.GetUserInfoEncryptionEnc())
	_ = d.Set("request_sign_alg", client.GetRequestSignAlg())
	_ = d.Set("request_encryption_alg", client.GetRequestEncryptionAlg())
	_ = d.Set("request_encryption_enc", client.GetRequestEncryptionEnc())
	_ = d.Set("token_auth_method", client.GetTokenAuthMethod())
	_ = d.Set("token_auth_sign_alg", client.GetTokenAuthSignAlg())
	_ = d.Set("default_max_age", client.GetDefaultMaxAge())
	_ = d.Set("default_acrs", client.GetDefaultAcrs())
	_ = d.Set("auth_time_required", client.GetAuthTimeRequired())
	_ = d.Set("login_uri", client.GetLoginUri())
	_ = d.Set("request_uris", client.GetRequestUris())
	_ = d.Set("description", client.GetDescription())
	_ = d.Set("descriptions", mapTaggedValuesFromDTO(client.GetDescriptions()))
	_ = d.Set("created_at", client.GetCreatedAt())
	_ = d.Set("modified_at", client.GetModifiedAt())
	clientExtension := client.GetExtension()
	_ = d.Set("requestable_scopes_enabled", clientExtension.GetRequestableScopesEnabled())
	_ = d.Set("requestable_scopes", clientExtension.GetRequestableScopes())
	_ = d.Set("access_token_duration", clientExtension.GetAccessTokenDuration())
	_ = d.Set("refresh_token_duration", clientExtension.GetRefreshTokenDuration())
	_ = d.Set("tls_client_auth_subject_dn", client.GetTlsClientAuthSubjectDn())
	_ = d.Set("tls_client_auth_san_dns", client.GetTlsClientAuthSanDns())
	_ = d.Set("tls_client_auth_san_uri", client.GetTlsClientAuthSanUri())
	_ = d.Set("tls_client_auth_san_ip", client.GetTlsClientAuthSanIp())
	_ = d.Set("tls_client_auth_san_email", client.GetTlsClientAuthSanEmail())
	_ = d.Set("tls_client_certificate_bound_access_tokens", client.GetTlsClientCertificateBoundAccessTokens())
	_ = d.Set("self_signed_certificate_key_id", client.GetSelfSignedCertificateKeyId())
	_ = d.Set("software_id", client.GetSoftwareId())
	_ = d.Set("software_version", client.GetSoftwareVersion())
	_ = d.Set("authorization_sign_alg", client.GetAuthorizationSignAlg())
	_ = d.Set("authorization_encryption_alg", client.GetAuthorizationEncryptionAlg())
	_ = d.Set("authorization_encryption_enc", client.GetAuthorizationEncryptionEnc())
	_ = d.Set("bc_delivery_mode", client.GetBcDeliveryMode())
	_ = d.Set("bc_notification_endpoint", client.GetBcNotificationEndpoint())
	_ = d.Set("bc_request_sign_alg", client.GetBcRequestSignAlg())
	_ = d.Set("bc_user_code_required", client.GetBcUserCodeRequired())
	_ = d.Set("dynamically_registered", client.GetDynamicallyRegistered())
	_ = d.Set("registration_access_token_hash", client.GetRegistrationAccessTokenHash())
	_ = d.Set("authorization_details_types", client.GetAuthorizationDetailsTypes())
	_ = d.Set("par_required", client.GetParRequired())
	_ = d.Set("request_object_required", client.GetRequestObjectRequired())
	_ = d.Set("attributes", mapAttributesFromDTO(client.GetAttributes()))
	_ = d.Set("custom_metadata", client.GetCustomMetadata())
	_ = d.Set("front_channel_request_object_encryption_required", client.GetFrontChannelRequestObjectEncryptionRequired())
	_ = d.Set("request_object_encryption_alg_match_required", client.GetRequestObjectEncryptionAlgMatchRequired())
	_ = d.Set("request_object_encryption_enc_match_required", client.GetRequestObjectEncryptionAlgMatchRequired())
	_ = d.Set("digest_algorithm", client.GetDigestAlgorithm())
	_ = d.Set("single_access_token_per_subject", client.GetSingleAccessTokenPerSubject())

}
