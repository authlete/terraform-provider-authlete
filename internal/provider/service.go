package provider

import (
	"context"
	"strconv"

	idp "github.com/authlete/idp-api"
	authlete3 "github.com/authlete/openapi-for-go/v3"
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
		CustomizeDiff: func(ctx context.Context, diff *schema.ResourceDiff, i interface{}) error {
			if diff.HasChange("supported_scopes") {
				old, new := diff.GetChange("supported_scopes")
				newScopes := new.(*schema.Set)
				scopes := new.(*schema.Set)

				for _, n := range newScopes.List() {
					var newMap = n.(map[string]interface{})
					if v, ok := newMap["name"]; ok {
						if isStandardScope(v.(string)) {
							for _, o := range old.(*schema.Set).List() {
								var oldMap = o.(map[string]interface{})
								if vOld, ok := oldMap["name"]; ok {
									if vOld.(string) == v.(string) {
										scopes.Remove(newMap)
										scopes.Add(oldMap)
									}
								}
							}
						}
					}
				}
				diff.SetNew("supported_scopes", scopes)
			}
			return nil
		},
		Schema: map[string]*schema.Schema{
			"service_name":                                     {Type: schema.TypeString, Required: true},
			"issuer":                                           {Type: schema.TypeString, Required: true},
			"description":                                      {Type: schema.TypeString, Required: false, Optional: true},
			"client_id_alias_enabled":                          {Type: schema.TypeBool, Required: false, Optional: true, Default: false},
			"attributes":                                       createAttributeSchema(),
			"supported_custom_client_metadata":                 createStringColSchema(),
			"authentication_callback_endpoint":                 {Type: schema.TypeString, Required: false, Optional: true},
			"authentication_callback_api_key":                  {Type: schema.TypeString, Required: false, Optional: true},
			"authentication_callback_api_secret":               {Type: schema.TypeString, Required: false, Optional: true},
			"supported_acrs":                                   createStringColSchema(),
			"supported_grant_types":                            createGrantTypeSchema(false),
			"supported_response_types":                         createResponseTypeSchema(false),
			"supported_authorization_detail_types":             createStringColSchema(), // supportedAuthorizationDetailsTypes field
			"supported_service_profiles":                       createSupportedFrameworkSchema(),
			"error_description_omitted":                        {Type: schema.TypeBool, Required: false, Optional: true},
			"error_uri_omitted":                                {Type: schema.TypeBool, Required: false, Optional: true},
			"authorization_endpoint":                           {Type: schema.TypeString, Required: false, Optional: true},
			"direct_authorization_endpoint_enabled":            {Type: schema.TypeBool, Required: false, Optional: true, Default: false},
			"supported_ui_locales":                             createStringColSchema(),
			"supported_displays":                               createSupportedDisplaySchema(),
			"pkce_required":                                    {Type: schema.TypeBool, Required: false, Optional: true},
			"pkce_s256_required":                               {Type: schema.TypeBool, Required: false, Optional: true},
			"authorization_response_duration":                  {Type: schema.TypeInt, Required: false, Optional: true},
			"iss_response_suppressed":                          {Type: schema.TypeBool, Required: false, Optional: true},                 // issSuppressed field
			"ignore_port_loopback_redirect":                    {Type: schema.TypeBool, Required: false, Optional: true, Computed: true}, // loopbackRedirectionUriVariable field
			"token_endpoint":                                   {Type: schema.TypeString, Required: false, Optional: true},
			"direct_token_endpoint_enabled":                    {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"supported_token_auth_methods":                     createClientAuthSchema(),
			"mutual_tls_validate_pki_cert_chain":               {Type: schema.TypeBool, Required: false, Optional: true},
			"trusted_root_certificates":                        createStringColSchema(),
			"missing_client_id_allowed":                        {Type: schema.TypeBool, Required: false, Optional: true},
			"revocation_endpoint":                              {Type: schema.TypeString, Required: false, Optional: true},
			"direct_revocation_endpoint_enabled":               {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"supported_revocation_auth_methods":                createClientAuthSchema(),
			"introspection_endpoint":                           {Type: schema.TypeString, Required: false, Optional: true},
			"direct_introspection_endpoint_enabled":            {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"supported_introspection_auth_methods":             createClientAuthSchema(),
			"pushed_auth_req_endpoint":                         {Type: schema.TypeString, Required: false, Optional: true},
			"pushed_auth_req_duration":                         {Type: schema.TypeInt, Required: false, Optional: true},
			"par_required":                                     {Type: schema.TypeBool, Required: false, Optional: true},
			"request_object_required":                          {Type: schema.TypeBool, Required: false, Optional: true},
			"traditional_request_object_processing_applied":    {Type: schema.TypeBool, Required: false, Optional: true},
			"nbf_optional":                                     {Type: schema.TypeBool, Required: false, Optional: true},
			"front_channel_encryption_request_obj_required":    {Type: schema.TypeBool, Required: false, Optional: true}, // frontChannelRequestObjectEncryptionRequired field
			"encryption_alg_req_obj_match":                     {Type: schema.TypeBool, Required: false, Optional: true}, // requestObjectEncryptionAlgMatchRequired field
			"encryption_enc_alg_req_obj_match":                 {Type: schema.TypeBool, Required: false, Optional: true}, // requestObjectEncryptionEncMatchRequired field
			"access_token_type":                                {Type: schema.TypeString, Required: false, Optional: true, Computed: true},
			"tls_client_certificate_bound_access_tokens":       {Type: schema.TypeBool, Required: false, Optional: true},
			"access_token_duration":                            {Type: schema.TypeInt, Required: false, Optional: true},
			"single_access_token_per_subject":                  {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"access_token_sign_alg":                            createSignAlgorithmSchema(),
			"access_token_signature_key_id":                    {Type: schema.TypeString, Required: false, Optional: true},
			"refresh_token_duration":                           {Type: schema.TypeInt, Required: false, Optional: true},
			"refresh_token_duration_kept":                      {Type: schema.TypeBool, Required: false, Optional: true},
			"refresh_token_duration_reset":                     {Type: schema.TypeBool, Required: false, Optional: true},
			"refresh_token_kept":                               {Type: schema.TypeBool, Required: false, Optional: true},
			"token_expiration_link":                            {Type: schema.TypeBool, Required: false, Optional: true}, // tokenExpirationLinked field
			"supported_scopes":                                 createSupportedScopeSchema(),
			"openid_dropped_on_refresh_without_offline_access": {Type: schema.TypeBool, Required: false, Optional: true},
			"scope_required":                                   {Type: schema.TypeBool, Required: false, Optional: true},
			"id_token_duration":                                {Type: schema.TypeInt, Required: false, Optional: true},
			"allowable_clock_skew":                             {Type: schema.TypeInt, Required: false, Optional: true},
			"supported_claim_types":                            createSupportedClaimTypesSchema(),
			"supported_claim_locales":                          createStringColSchema(),
			"supported_claims":                                 createStringColSchema(),
			"claim_shortcut_restrictive":                       {Type: schema.TypeBool, Required: false, Optional: true},
			"jwks_endpoint":                                    {Type: schema.TypeString, Required: false, Optional: true}, // jwksUri field
			"direct_jwks_endpoint_enabled":                     {Type: schema.TypeBool, Required: false, Optional: true, Default: false},
			"jwk":                                              createJWKSchema(), // jwks field
			"id_token_signature_key_id":                        {Type: schema.TypeString, Required: false, Optional: true},
			"user_info_signature_key_id":                       {Type: schema.TypeString, Required: false, Optional: true},
			"authorization_signature_key_id":                   {Type: schema.TypeString, Required: false, Optional: true},
			"hsm_enabled":                                      {Type: schema.TypeBool, Required: false, Optional: true},
			"user_info_endpoint":                               {Type: schema.TypeString, Required: false, Optional: true},
			"direct_user_info_endpoint_enabled":                {Type: schema.TypeBool, Required: false, Optional: true, Default: false},
			"dynamic_registration_supported":                   {Type: schema.TypeBool, Required: false, Optional: true},
			"dcr_scope_used_as_requestable":                    {Type: schema.TypeBool, Required: false, Optional: true, Computed: true},
			"registration_endpoint":                            {Type: schema.TypeString, Required: false, Optional: true},
			"registration_management_endpoint":                 {Type: schema.TypeString, Required: false, Optional: true},
			"mtls_endpoint_aliases":                            createMtlsEndpointSchema(),
			"policy_uri":                                       {Type: schema.TypeString, Required: false, Optional: true},
			"tos_uri":                                          {Type: schema.TypeString, Required: false, Optional: true},
			"service_documentation":                            {Type: schema.TypeString, Required: false, Optional: true},
			"backchannel_authentication_endpoint":              {Type: schema.TypeString, Required: false, Optional: true},
			"supported_backchannel_token_delivery_modes":       createBackchannelDeliverySchema(),
			"backchannel_auth_req_id_duration":                 {Type: schema.TypeInt, Required: false, Optional: true},
			"backchannel_polling_interval":                     {Type: schema.TypeInt, Required: false, Optional: true},
			"backchannel_user_code_parameter_supported":        {Type: schema.TypeBool, Required: false, Optional: true},
			"backchannel_binding_message_required_in_fapi":     {Type: schema.TypeBool, Required: false, Optional: true},
			"device_authorization_endpoint":                    {Type: schema.TypeString, Required: false, Optional: true},
			"device_verification_uri":                          {Type: schema.TypeString, Required: false, Optional: true},
			"device_verification_uri_complete":                 {Type: schema.TypeString, Required: false, Optional: true},
			"device_flow_code_duration":                        {Type: schema.TypeInt, Required: false, Optional: true},
			"device_flow_polling_interval":                     {Type: schema.TypeInt, Required: false, Optional: true},
			"user_code_charset":                                createUserCodeCharsetSchema(),
			"user_code_length":                                 {Type: schema.TypeInt, Required: false, Optional: true},
			"supported_trust_frameworks":                       createStringColSchema(),
			"supported_evidence":                               createStringColSchema(),
			"supported_documents":                              createStringColSchema(),
			"supported_verification_methods":                   createStringColSchema(),
			"supported_verified_claims":                        createStringColSchema(),
			"verified_claims_validation_schema_set":            createVerifiedClaimsType(),
			"end_session_endpoint":                             {Type: schema.TypeString, Required: false, Optional: true},
			"dcr_duplicate_software_id_blocked":                {Type: schema.TypeBool, Required: false, Optional: true},
			"request_object_audience_checked":                  {Type: schema.TypeBool, Required: false, Optional: true},
			"access_token_for_external_attachment_embedded":    {Type: schema.TypeBool, Required: false, Optional: true},
			"authority_hints":                                  createStringColSchema(),
			"federation_enabled":                               {Type: schema.TypeBool, Required: false, Optional: true},
			"federation_jwk":                                   createJWKSchema(), // federationJwks field
			"federation_signature_key_id":                      {Type: schema.TypeString, Required: false, Optional: true},
			"federation_configuration_duration":                {Type: schema.TypeInt, Required: false, Optional: true},
			"federation_registration_endpoint":                 {Type: schema.TypeString, Required: false, Optional: true},
			"organization_name":                                {Type: schema.TypeString, Required: false, Optional: true},
			"predefined_transformed_claims":                    {Type: schema.TypeString, Required: false, Optional: true},
			"refresh_token_idempotent":                         {Type: schema.TypeBool, Required: false, Optional: true},
			"signed_jwks_uri":                                  {Type: schema.TypeString, Required: false, Optional: true},
			"supported_attachments":                            createSupportedAttachmentsSchema(),
			"supported_digest_algorithms":                      createStringColSchema(),
			"supported_documents_methods":                      createStringColSchema(),
			"supported_documents_validation_methods":           createStringColSchema(),
			"supported_documents_verification_methods":         createStringColSchema(),
			"supported_electronic_records":                     createStringColSchema(),
			"supported_client_registration_types":              createClientRegistrationSchema(),
			"token_exchange_by_identifiable_clients_only":      {Type: schema.TypeBool, Required: false, Optional: true},
			"token_exchange_by_confidential_clients_only":      {Type: schema.TypeBool, Required: false, Optional: true},
			"token_exchange_by_permitted_clients_only":         {Type: schema.TypeBool, Required: false, Optional: true},
			"token_exchange_encrypted_jwt_rejected":            {Type: schema.TypeBool, Required: false, Optional: true},
			"token_exchange_unsigned_jwt_rejected":             {Type: schema.TypeBool, Required: false, Optional: true},
			"jwt_grant_by_identifiable_clients_only":           {Type: schema.TypeBool, Required: false, Optional: true},
			"jwt_grant_encrypted_jwt_rejected":                 {Type: schema.TypeBool, Required: false, Optional: true},
			"jwt_grant_unsigned_jwt_rejected":                  {Type: schema.TypeBool, Required: false, Optional: true},
			"trust_anchors":                                    createTrustAnchorSchema(),
		},
	}
}

func serviceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	client := meta.(*apiClient)

	var diags diag.Diagnostics

	tflog.Trace(ctx, "Creating a new service")

	apiServerId, err := strconv.Atoi(client.apiServerId)
	if err != nil {
		return diag.FromErr(err)
	}
	organizationId, err := strconv.Atoi(client.organizationId)
	if err != nil {
		return diag.FromErr(err)
	}
	newServiceDto, _ := dataToService(d, diags, idp.NewService())
	nService := (*newServiceDto)
	createSvcReq := idp.NewCreateServiceRequest(int64(apiServerId), int64(organizationId))
	createSvcReq.SetService(nService)
	orgToken := convertToBearerToken(client.serviceOwnerSecret)
	r, _, err := client.authleteClient.idp.ServiceApiAPI.CreateService(ctx).CreateServiceRequest(*createSvcReq).Authorization(orgToken).Execute()
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Trace(ctx, "Service created")

	apiKey := r.ApiKey
	
	diags = serviceIdpToResource(r, d)

	d.SetId(strconv.FormatInt(*apiKey, 10))

	return diags

}

func serviceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics
	return serviceReadInternal(ctx, d, meta, diags)
}

func serviceReadInternal(_ context.Context, d *schema.ResourceData, meta interface{}, diags diag.Diagnostics) diag.Diagnostics {
	client := meta.(*apiClient)

	auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, client.serviceOwnerSecret)
	dto, _, err := client.authleteClient.v3.ServiceManagementAPI.ServiceGetApi(auth, d.Id()).Execute()

	if err != nil {
		return diag.FromErr(err)
	}
	diags = serviceToResource(*dto.Service, d)
	return diags

}

func serviceUpdate(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	var diags diag.Diagnostics

	client := meta.(*apiClient)

	auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, client.serviceOwnerSecret)

	srv, _, err := client.authleteClient.v3.ServiceManagementAPI.ServiceGetApi(auth, d.Id()).Execute()
	if err != nil {
		return diag.FromErr(err)
	}

	setDataToService(d, diags, *srv.Service)

	aSrv, _, err := client.authleteClient.v3.ServiceManagementAPI.ServiceUpdateApi(auth, d.Id()).Service(*srv.Service).Execute()

	if err != nil {
		return diag.FromErr(err)
	}
	diags = serviceToResource(*aSrv, d)

	return diags

}

func serviceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	// client := meta.(*apiClient)

	client := meta.(*apiClient)
	var err error = nil

	var apiServerId int
	var organizationId int
	var serviceId int
	orgToken := convertToBearerToken(client.serviceOwnerSecret)
	apiServerId, err = strconv.Atoi(client.apiServerId)
	if err != nil {
		return diag.FromErr(err)
	}
	organizationId, err = strconv.Atoi(client.organizationId)
	if err != nil {
		return diag.FromErr(err)
	}
	serviceId, err = strconv.Atoi(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	deleteSvcReq := idp.NewDeleteServiceRequest(int64(apiServerId), int64(organizationId), int64(serviceId))

	_, err = client.authleteClient.idp.ServiceApiAPI.DeleteService(ctx).Authorization(orgToken).DeleteServiceRequest(*deleteSvcReq).Execute()

	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func mapSetToString(vals []interface{}) []string {
	values := make([]string, len(vals))

	for i, v := range vals {
		if v != nil {
			values[i] = v.(string)
		}
	}

	return values
}

func mapSchemaFromString(vals []string) []interface{} {
	if vals != nil {
		entries := make([]interface{}, len(vals))
		for i, v := range vals {
			entries[i] = v
		}
		return entries
	}
	return make([]interface{}, 0)
}

func createStringColSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
	}
}

func isStandardScope(scopeName string) bool {
	standardScopes := []string{"address", "email", "openid", "offline_access", "phone", "profile"}
	for _, v := range standardScopes {
		if v == scopeName {
			return true
		}
	}
	return false
}
