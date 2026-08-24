resource "authlete_service" "my_service" {
  access_token_duration                         = 7
  access_token_for_external_attachment_embedded = true
  access_token_sign_alg                         = "HS256"
  access_token_signature_key_id                 = "...my_access_token_signature_key_id..."
  access_token_type                             = "...my_access_token_type..."
  allowable_clock_skew                          = 0
  api_server_id                                 = 10
  attestation_challenge_time_window             = 4
  attributes = [
    {
      key   = "...my_key..."
      value = "...my_value..."
    }
  ]
  authentication_callback_api_key    = "...my_authentication_callback_api_key..."
  authentication_callback_api_secret = "...my_authentication_callback_api_secret..."
  authentication_callback_endpoint   = "https://adolescent-dream.com"
  authority_hints = [
    "..."
  ]
  authorization_code_duration                  = 10
  authorization_endpoint                       = "https://trained-analogy.biz/"
  authorization_response_duration              = 10
  authorization_signature_key_id               = "...my_authorization_signature_key_id..."
  backchannel_auth_req_id_duration             = 2
  backchannel_authentication_endpoint          = "https://ornery-anticodon.com/"
  backchannel_binding_message_required_in_fapi = false
  backchannel_logout_session_supported         = true
  backchannel_logout_supported                 = false
  backchannel_polling_interval                 = 8
  backchannel_user_code_parameter_supported    = false
  cimd_allowlist = [
    "..."
  ]
  cimd_allowlist_enabled                    = true
  cimd_always_retrieved                     = false
  cimd_http_permitted                       = false
  cimd_metadata_policy                      = "...my_cimd_metadata_policy..."
  cimd_metadata_policy_enabled              = false
  cimd_query_permitted                      = true
  claim_shortcut_restrictive                = false
  client_assertion_aud_restricted_to_issuer = false
  client_attester_roots = [
    "..."
  ]
  client_attester_roots_enabled         = false
  client_attester_roots_only            = false
  client_id_alias_enabled               = true
  client_id_metadata_document_supported = true
  clients_per_developer                 = 9
  cnonce_duration                       = 10
  credential_duration                   = 9
  credential_issuer_metadata = {
    authorization_servers = [
      "..."
    ]
    batch_credential_endpoint = "https://poor-morning.name"
    batch_size                = 5
    credential_endpoint       = "https://vivid-molasses.net"
    credential_issuer         = "...my_credential_issuer..."
    credential_response_encryption_alg_values_supported = [
      "..."
    ]
    credential_response_encryption_enc_values_supported = [
      "..."
    ]
    credential_response_encryption_zip_values_supported = [
      "..."
    ]
    credentials_supported                  = "...my_credentials_supported..."
    deferred_credential_endpoint           = "...my_deferred_credential_endpoint..."
    require_credential_request_encryption  = true
    require_credential_response_encryption = true
  }
  credential_jwks                              = "...my_credential_jwks..."
  credential_jwks_uri                          = "...my_credential_jwks_uri..."
  credential_offer_duration                    = 5
  credential_transaction_duration              = 1
  dcr_duplicate_software_id_blocked            = false
  dcr_scope_used_as_requestable                = true
  description                                  = "...my_description..."
  developer_authentication_callback_api_key    = "...my_developer_authentication_callback_api_key..."
  developer_authentication_callback_api_secret = "...my_developer_authentication_callback_api_secret..."
  developer_authentication_callback_endpoint   = "https://male-colonialism.com/"
  device_authorization_endpoint                = "https://nimble-secrecy.name/"
  device_flow_code_duration                    = 8
  device_flow_polling_interval                 = 3
  device_verification_uri                      = "https://brilliant-cannon.biz/"
  device_verification_uri_complete             = "https://agile-handover.name"
  direct_authorization_endpoint_enabled        = false
  direct_introspection_endpoint_enabled        = true
  direct_jwks_endpoint_enabled                 = false
  direct_revocation_endpoint_enabled           = true
  direct_token_endpoint_enabled                = true
  direct_user_info_endpoint_enabled            = false
  dpop_nonce_duration                          = 4
  dpop_nonce_required                          = false
  dynamic_registration_supported               = false
  end_session_endpoint                         = "https://defensive-casket.net/"
  error_description_omitted                    = false
  error_uri_omitted                            = true
  fapi_modes = [
    "FAPI2_MESSAGE_SIGNING_AUTH_RES"
  ]
  federation_configuration_duration                = 8
  federation_enabled                               = false
  federation_jwks                                  = "...my_federation_jwks..."
  federation_registration_endpoint                 = "...my_federation_registration_endpoint..."
  federation_signature_key_id                      = "...my_federation_signature_key_id..."
  front_channel_request_object_encryption_required = false
  grant_management_action_required                 = true
  grant_management_endpoint                        = "...my_grant_management_endpoint..."
  hsks = [
    {
      alg        = "...my_alg..."
      handle     = "...my_handle..."
      hsm_name   = "...my_hsm_name..."
      kid        = "...my_kid..."
      kty        = "...my_kty..."
      public_key = "...my_public_key..."
      use        = "...my_use..."
    }
  ]
  hsm_enabled                            = true
  http_alias_prohibited                  = true
  id_token_aud_type                      = "...my_id_token_aud_type..."
  id_token_duration                      = 10
  id_token_reissuable                    = true
  id_token_signature_key_id              = "...my_id_token_signature_key_id..."
  introspection_endpoint                 = "https://coordinated-hovel.info/"
  introspection_signature_key_id         = "...my_introspection_signature_key_id..."
  iss_suppressed                         = true
  issuer                                 = "...my_issuer..."
  jwks                                   = "...my_jwks..."
  jwks_uri                               = "https://black-publication.com/"
  jwt_grant_by_identifiable_clients_only = false
  jwt_grant_encrypted_jwt_rejected       = true
  jwt_grant_unsigned_jwt_rejected        = true
  key_attester_roots = [
    "..."
  ]
  key_attester_roots_enabled        = true
  key_attester_roots_only           = true
  loopback_redirection_uri_variable = true
  metadata = [
    {
      key   = "...my_key..."
      value = "...my_value..."
    }
  ]
  missing_client_id_allowed = true
  mtls_endpoint_aliases = [
    {
      name = "...my_name..."
      uri  = "https://handy-guide.name"
    }
  ]
  mutual_tls_validate_pki_cert_chain               = false
  native_sso_supported                             = false
  nbf_optional                                     = false
  oid4vci_version                                  = "...my_oid4vci_version..."
  openid_dropped_on_refresh_without_offline_access = false
  organization_id                                  = 9
  organization_name                                = "...my_organization_name..."
  par_required                                     = false
  pkce_required                                    = true
  pkce_s256_required                               = false
  policy_uri                                       = "https://hateful-polyester.org/"
  pre_authorized_grant_anonymous_access_supported  = false
  predefined_transformed_claims                    = "...my_predefined_transformed_claims..."
  pushed_auth_req_duration                         = 10
  pushed_auth_req_endpoint                         = "https://edible-topsail.org/"
  refresh_token_duration                           = 0
  refresh_token_duration_kept                      = true
  refresh_token_duration_reset                     = false
  refresh_token_idempotent                         = false
  refresh_token_kept                               = false
  registration_endpoint                            = "https://edible-reasoning.net/"
  registration_management_endpoint                 = "https://corrupt-brief.info"
  request_object_audience_checked                  = false
  request_object_encryption_alg_match_required     = true
  request_object_encryption_enc_match_required     = false
  request_object_required                          = true
  resource_signature_key_id                        = "...my_resource_signature_key_id..."
  revocation_endpoint                              = "https://true-planula.biz"
  rs_response_signed                               = true
  scope_required                                   = false
  server_url                                       = "https://login.authlete.com"
  service_documentation                            = "https://shrill-noon.name"
  service_name                                     = "...my_service_name..."
  signed_jwks_uri                                  = "...my_signed_jwks_uri..."
  single_access_token_per_subject                  = true
  sns_credentials = [
    {
      api_key    = "...my_api_key..."
      api_secret = "...my_api_secret..."
      sns        = "...my_sns..."
    }
  ]
  supported_attachments = [
    "EMBEDDED"
  ]
  supported_authorization_details_types = [
    "..."
  ]
  supported_backchannel_token_delivery_modes = [
    "POLL"
  ]
  supported_claim_locales = [
    "..."
  ]
  supported_claim_types = [
    "AGGREGATED"
  ]
  supported_claims = [
    "..."
  ]
  supported_client_registration_types = [
    "EXPLICIT"
  ]
  supported_custom_client_metadata = [
    "..."
  ]
  supported_digest_algorithms = [
    "..."
  ]
  supported_displays = [
    "POPUP"
  ]
  supported_documents = [
    "..."
  ]
  supported_documents_check_methods = [
    "..."
  ]
  supported_documents_methods = [
    "..."
  ]
  supported_documents_validation_methods = [
    "..."
  ]
  supported_documents_verification_methods = [
    "..."
  ]
  supported_electronic_records = [
    "..."
  ]
  supported_evidence = [
    "..."
  ]
  supported_grant_types = [
    "IMPLICIT"
  ]
  supported_identity_documents = [
    "..."
  ]
  supported_introspection_auth_methods = [
    "SELF_SIGNED_TLS_CLIENT_AUTH"
  ]
  supported_prompt_values = [
    "NONE"
  ]
  supported_response_types = [
    "TOKEN"
  ]
  supported_revocation_auth_methods = [
    "ATTEST_JWT_CLIENT_AUTH"
  ]
  supported_scopes = [
    {
      attributes = [
        {
          key   = "...my_key..."
          value = "...my_value..."
        }
      ]
      default_entry = false
      description   = "...my_description..."
      descriptions = [
        {
          tag   = "...my_tag..."
          value = "...my_value..."
        }
      ]
      name = "...my_name..."
    }
  ]
  supported_service_profiles = [
    "OPEN_BANKING"
  ]
  supported_snses = [
    "FACEBOOK"
  ]
  supported_token_auth_methods = [
    "TLS_CLIENT_AUTH"
  ]
  supported_trust_frameworks = [
    "..."
  ]
  supported_ui_locales = [
    "..."
  ]
  supported_verification_methods = [
    "..."
  ]
  supported_verified_claims = [
    "..."
  ]
  tls_client_certificate_bound_access_tokens    = false
  token_batch_notification_endpoint             = "https://narrow-yak.biz"
  token_endpoint                                = "https://breakable-decongestant.net/"
  token_exchange_by_confidential_clients_only   = true
  token_exchange_by_identifiable_clients_only   = true
  token_exchange_by_permitted_clients_only      = true
  token_exchange_encrypted_jwt_rejected         = false
  token_exchange_unsigned_jwt_rejected          = true
  token_expiration_linked                       = true
  tos_uri                                       = "https://informal-guide.info/"
  traditional_request_object_processing_applied = true
  trust_anchors = [
    {
      entity_id = "...my_entity_id..."
      jwks      = "...my_jwks..."
    }
  ]
  trusted_root_certificates = [
    "..."
  ]
  unauthorized_on_client_config_supported = false
  user_code_charset                       = "NUMERIC"
  user_code_length                        = 5
  user_info_endpoint                      = "https://burdensome-jogging.net"
  user_info_signature_key_id              = "...my_user_info_signature_key_id..."
  user_pin_length                         = 6
  verifiable_credentials_enabled          = false
  verified_claims_validation_schema_set   = "standard"
}