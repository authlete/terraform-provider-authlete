package provider

import (
	"context"
	"strconv"

	"github.com/authlete/authlete-go/api"
	"github.com/authlete/authlete-go/conf"
	"github.com/authlete/authlete-go/dto"
	"github.com/authlete/authlete-go/types"
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
	authleteClient := resolveAuthleteClient(meta, d)

	newClientDto := dataToClient(d)
	newClient, err := authleteClient.CreateClient(&newClientDto)

	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Client created")
	updateResourceFromClient(d, newClient)
	d.SetId(strconv.FormatUint(newClient.ClientId, 10))
	return diags
}

func clientRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	authleteClient := resolveAuthleteClient(meta, d)
	clientDto, err := authleteClient.GetClient(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	updateResourceFromClient(d, clientDto)
	return diags
}

func clientUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics

	tflog.Trace(ctx, "Updating client")
	authleteClient := resolveAuthleteClient(meta, d)

	newClientDto := dataToClient(d)
	id, _ := strconv.Atoi(d.Id())
	newClientDto.ClientId = uint64(id)
	newClient, err := authleteClient.UpdateClient(&newClientDto)

	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Client updated")
	updateResourceFromClient(d, newClient)
	d.SetId(strconv.FormatUint(newClient.ClientId, 10))
	return diags

}

func clientDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	authleteClient := resolveAuthleteClient(meta, d)
	err := authleteClient.DeleteClient(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	return diags
}

func resolveAuthleteClient(meta interface{}, d *schema.ResourceData) api.AuthleteApi {
	client := meta.(*apiClient)
	authleteClient := client.authleteClient
	if d.Get("apikey") != "" && client.api_key != d.Get("apikey") {
		cnf := conf.AuthleteSimpleConfiguration{}
		cnf.SetBaseUrl(client.api_server)
		cnf.SetServiceApiKey(d.Get("apikey").(string))
		cnf.SetServiceApiSecret(d.Get("apisecret").(string))

		authleteClient = api.New(&cnf)
	}
	return authleteClient
}

func dataToClient(d *schema.ResourceData) dto.Client {

	ext := dto.ClientExtension{
		RequestableScopesEnabled: d.Get("requestable_scopes_enabled").(bool),
		RequestableScopes:        mapSetToString(d.Get("requestable_scopes").([]interface{})),
		AccessTokenDuration:      uint64(d.Get("access_token_duration").(int)),
		RefreshTokenDuration:     uint64(d.Get("refresh_token_duration").(int)),
	}

	newClient := dto.Client{
		Developer:                             d.Get("developer").(string),
		ClientId:                              uint64(d.Get("client_id").(int)),
		ClientIdAlias:                         d.Get("client_id_alias").(string),
		ClientIdAliasEnabled:                  d.Get("client_id_alias_enabled").(bool),
		ClientType:                            types.ClientType(d.Get("client_type").(string)),
		RedirectUris:                          mapSetToString(d.Get("redirect_uris").([]interface{})),
		ResponseTypes:                         mapResponseTypesToDTO(d.Get("response_types").([]interface{})),
		GrantTypes:                            mapGrantTypesToDTO(d.Get("grant_types").([]interface{})),
		ApplicationType:                       mapApplicationTypeToDto(d.Get("application_type")),
		Contacts:                              mapSetToString(d.Get("contacts").([]interface{})),
		ClientName:                            d.Get("client_name").(string),
		ClientNames:                           mapTaggedValuestoDto(d.Get("client_names").([]interface{})),
		LogoUri:                               d.Get("logo_uri").(string),
		LogoUris:                              mapTaggedValuestoDto(d.Get("logo_uris").([]interface{})),
		ClientUri:                             d.Get("client_uri").(string),
		ClientUris:                            mapTaggedValuestoDto(d.Get("client_uris").([]interface{})),
		PolicyUri:                             d.Get("policy_uri").(string),
		PolicyUris:                            mapTaggedValuestoDto(d.Get("policy_uris").([]interface{})),
		TosUri:                                d.Get("tos_uri").(string),
		TosUris:                               mapTaggedValuestoDto(d.Get("tos_uris").([]interface{})),
		JwksUri:                               d.Get("jwks_uri").(string),
		Jwks:                                  d.Get("jwks").(string),
		DerivedSectorIdentifier:               d.Get("derived_sector_identifier").(string),
		SectorIdentifierUri:                   d.Get("sector_identifier_uri").(string),
		SubjectType:                           mapSubjectTypeToDto(d.Get("subject_type")),
		IdTokenSignAlg:                        mapJWSAlg(d.Get("id_token_sign_alg")),
		IdTokenEncryptionAlg:                  mapJWEAlg(d.Get("id_token_encryption_alg")),
		IdTokenEncryptionEnc:                  mapJWEEnc(d.Get("id_token_encryption_enc")),
		UserInfoSignAlg:                       mapJWSAlg(d.Get("user_info_sign_alg")),
		UserInfoEncryptionAlg:                 mapJWEAlg(d.Get("user_info_encryption_alg")),
		UserInfoEncryptionEnc:                 mapJWEEnc(d.Get("user_info_encryption_enc")),
		RequestSignAlg:                        mapJWSAlg(d.Get("request_sign_alg")),
		RequestEncryptionAlg:                  mapJWEAlg(d.Get("request_encryption_alg")),
		RequestEncryptionEnc:                  mapJWEEnc(d.Get("request_encryption_enc")),
		TokenAuthMethod:                       mapClientAuthMethodToDto(d.Get("token_auth_method")),
		TokenAuthSignAlg:                      mapJWSAlg(d.Get("token_auth_sign_alg")),
		DefaultMaxAge:                         uint32(d.Get("default_max_age").(int)),
		DefaultAcrs:                           mapSetToString(d.Get("default_acrs").([]interface{})),
		AuthTimeRequired:                      d.Get("auth_time_required").(bool),
		LoginUri:                              d.Get("login_uri").(string),
		RequestUris:                           mapSetToString(d.Get("request_uris").([]interface{})),
		Description:                           d.Get("description").(string),
		Descriptions:                          mapTaggedValuestoDto(d.Get("descriptions").([]interface{})),
		Extension:                             ext,
		TlsClientAuthSubjectDn:                d.Get("tls_client_auth_subject_dn").(string),
		TlsClientAuthSanDns:                   d.Get("tls_client_auth_san_dns").(string),
		TlsClientAuthSanUri:                   d.Get("tls_client_auth_san_uri").(string),
		TlsClientAuthSanIp:                    d.Get("tls_client_auth_san_ip").(string),
		TlsClientAuthSanEmail:                 d.Get("tls_client_auth_san_email").(string),
		TlsClientCertificateBoundAccessTokens: d.Get("tls_client_certificate_bound_access_tokens").(bool),
		SelfSignedCertificateKeyId:            d.Get("self_signed_certificate_key_id").(string),
		SoftwareId:                            d.Get("software_id").(string),
		SoftwareVersion:                       d.Get("software_version").(string),
		AuthorizationSignAlg:                  mapJWSAlg(d.Get("authorization_sign_alg")),
		AuthorizationEncryptionAlg:            mapJWEAlg(d.Get("authorization_encryption_alg")),
		AuthorizationEncryptionEnc:            mapJWEEnc(d.Get("authorization_encryption_enc")),
		BcDeliveryMode:                        mapDeliveryModeToDto(d.Get("bc_delivery_mode")),
		BcNotificationEndpoint:                d.Get("bc_notification_endpoint").(string),
		BcRequestSignAlg:                      mapJWSAlg(d.Get("bc_request_sign_alg")),
		BcUserCodeRequired:                    d.Get("bc_user_code_required").(bool),
		DynamicallyRegistered:                 d.Get("dynamically_registered").(bool),
		RegistrationAccessTokenHash:           d.Get("registration_access_token_hash").(string),
		AuthorizationDetailsTypes:             mapSetToString(d.Get("authorization_details_types").([]interface{})),
		ParRequired:                           d.Get("par_required").(bool),
		RequestObjectRequired:                 d.Get("request_object_required").(bool),
		Attributes:                            mapAttributestoDto(d.Get("attributes").([]interface{})),
		CustomMetadata:                        d.Get("custom_metadata").(string),
		FrontChannelRequestObjectEncryptionRequired: d.Get("front_channel_request_object_encryption_required").(bool),
		RequestObjectEncryptionAlgMatchRequired:     d.Get("request_object_encryption_alg_match_required").(bool),
		RequestObjectEncryptionEncMatchRequired:     d.Get("request_object_encryption_enc_match_required").(bool),
	}

	return newClient
}

func updateResourceFromClient(d *schema.ResourceData, client *dto.Client) {
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
	d.Set("logo_uris", mapTaggedValuesfromDto(&client.LogoUris))
	d.Set("client_uri", client.ClientUri)
	d.Set("client_uris", mapTaggedValuesfromDto(&client.ClientUris))
	d.Set("policy_uri", client.PolicyUri)
	d.Set("policy_uris", mapTaggedValuesfromDto(&client.PolicyUris))
	d.Set("tos_uri", client.TosUri)
	d.Set("tos_uris", mapTaggedValuesfromDto(&client.TosUris))
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
	d.Set("descriptions", mapTaggedValuesfromDto(&client.Descriptions))
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
	d.Set("attributes", mapAttributesfromDto(&client.Attributes))
	d.Set("custom_metadata", client.CustomMetadata)
	d.Set("front_channel_request_object_encryption_required", client.FrontChannelRequestObjectEncryptionRequired)
	d.Set("request_object_encryption_alg_match_required", client.RequestObjectEncryptionAlgMatchRequired)
	d.Set("request_object_encryption_enc_match_required", client.RequestObjectEncryptionAlgMatchRequired)

}
