resource "authlete_client" "my_client" {
  application_type = "NATIVE"
  attributes = [
    {
      key   = "...my_key..."
      value = "...my_value..."
    }
  ]
  auth_time_required = false
  authorization_details_types = [
    "..."
  ]
  authorization_encryption_alg        = "RSA1_5"
  authorization_encryption_enc        = "A256CBC_HS512"
  authorization_sign_alg              = "EdDSA"
  automatically_registered            = true
  backchannel_logout_session_required = true
  backchannel_logout_uri              = "...my_backchannel_logout_uri..."
  bc_delivery_mode                    = "...my_bc_delivery_mode..."
  bc_notification_endpoint            = "...my_bc_notification_endpoint..."
  bc_request_sign_alg                 = "RS384"
  bc_user_code_required               = false
  client_id_alias                     = "...my_client_id_alias..."
  client_id_alias_enabled             = false
  client_name                         = "...my_client_name..."
  client_names = [
    {
      tag   = "...my_tag..."
      value = "...my_value..."
    }
  ]
  client_registration_types = [
    "AUTOMATIC"
  ]
  client_source = "DYNAMIC_REGISTRATION"
  client_type   = "PUBLIC"
  client_uri    = "...my_client_uri..."
  client_uris = [
    {
      tag   = "...my_tag..."
      value = "...my_value..."
    }
  ]
  contacts = [
    "..."
  ]
  credential_offer_endpoint               = "...my_credential_offer_endpoint..."
  credential_response_encryption_required = false
  custom_metadata                         = "...my_custom_metadata..."
  default_acrs = [
    "..."
  ]
  default_max_age = 5
  description     = "...my_description..."
  descriptions = [
    {
      tag   = "...my_tag..."
      value = "...my_value..."
    }
  ]
  developer                       = "...my_developer..."
  digest_algorithm                = "...my_digest_algorithm..."
  discovered_by_metadata_document = true
  dpop_required                   = true
  entity_id                       = "...my_entity_id..."
  explicitly_registered           = false
  extension = {
    access_token_duration  = 9
    id_token_duration      = 9
    refresh_token_duration = 2
    requestable_scopes = [
      "..."
    ]
    requestable_scopes_enabled = false
    token_exchange_permitted   = true
  }
  fapi_modes = [
    "FAPI1_ADVANCED"
  ]
  front_channel_request_object_encryption_required = false
  grant_types = [
    "CLIENT_CREDENTIALS"
  ]
  id_token_encryption_alg      = "A128GCMKW"
  id_token_encryption_enc      = "A256GCM"
  id_token_sign_alg            = "PS256"
  in_scope_for_token_migration = true
  jwks                         = "...my_jwks..."
  jwks_uri                     = "...my_jwks_uri..."
  locked                       = true
  login_uri                    = "...my_login_uri..."
  logo_uri                     = "...my_logo_uri..."
  logo_uris = [
    {
      tag   = "...my_tag..."
      value = "...my_value..."
    }
  ]
  metadata_document_expires_at = 4
  metadata_document_location   = "https://free-detective.info/"
  metadata_document_updated_at = 1
  mtls_endpoint_aliases_used   = true
  organization_name            = "...my_organization_name..."
  par_required                 = false
  pkce_required                = false
  pkce_s256_required           = true
  policy_uri                   = "...my_policy_uri..."
  policy_uris = [
    {
      tag   = "...my_tag..."
      value = "...my_value..."
    }
  ]
  redirect_uris = [
    "..."
  ]
  registration_access_token_hash               = "...my_registration_access_token_hash..."
  request_encryption_alg                       = "RSA_OAEP"
  request_encryption_enc                       = "A192GCM"
  request_object_encryption_alg_match_required = false
  request_object_encryption_enc_match_required = false
  request_object_required                      = false
  request_sign_alg                             = "PS256"
  request_uris = [
    "..."
  ]
  response_modes = [
    "FORM_POST"
  ]
  response_types = [
    "NONE"
  ]
  rs_request_signed                          = false
  rs_signed_request_key_id                   = "...my_rs_signed_request_key_id..."
  sector_identifier_uri                      = "...my_sector_identifier_uri..."
  self_signed_certificate_key_id             = "...my_self_signed_certificate_key_id..."
  service_id                                 = "...my_service_id..."
  signed_jwks_uri                            = "...my_signed_jwks_uri..."
  single_access_token_per_subject            = true
  software_id                                = "...my_software_id..."
  software_version                           = "...my_software_version..."
  spiffe_bundle_endpoint                     = "...my_spiffe_bundle_endpoint..."
  spiffe_id                                  = "...my_spiffe_id..."
  subject_type                               = "PAIRWISE"
  tls_client_auth_san_dns                    = "...my_tls_client_auth_san_dns..."
  tls_client_auth_san_email                  = "...my_tls_client_auth_san_email..."
  tls_client_auth_san_ip                     = "...my_tls_client_auth_san_ip..."
  tls_client_auth_san_uri                    = "...my_tls_client_auth_san_uri..."
  tls_client_auth_subject_dn                 = "...my_tls_client_auth_subject_dn..."
  tls_client_certificate_bound_access_tokens = true
  token_auth_method                          = "TLS_CLIENT_AUTH"
  token_auth_sign_alg                        = "HS256"
  tos_uri                                    = "...my_tos_uri..."
  tos_uris = [
    {
      tag   = "...my_tag..."
      value = "...my_value..."
    }
  ]
  trust_anchor_id = "...my_trust_anchor_id..."
  trust_chain = [
    "..."
  ]
  trust_chain_expires_at   = 5
  trust_chain_updated_at   = 0
  user_info_encryption_alg = "A192KW"
  user_info_encryption_enc = "A192GCM"
  user_info_sign_alg       = "NONE"
}