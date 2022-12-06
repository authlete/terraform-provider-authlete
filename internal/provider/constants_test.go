package provider

// Scenarios for simple service tests

const testAccResourceServiceDefaultValues = `
provider "authlete" {
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Simplest Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
}

output "api_key" {  
  value = authlete_service.prod.id
}
output "api_secret" {  
  value = authlete_service.prod.api_secret
}
`

const testAccResourceServiceEveryAttribute = `

provider "authlete" {
	
}

resource "authlete_service" "complete_described" {
  service_name = "attributes coverage test"
  issuer = "https://test.com"
  description = "Attributes support test"
  clients_per_developer = 1
  client_id_alias_enabled = true
  attribute {
  	 key = "require_2_fa"
     value = "true"
  }
  attribute {
  	 key = "high_risk_scopes"
     value = "scope1 scope2 scope3"
  }
  supported_custom_client_metadata = ["basic_review", "domain_match"]
  authentication_callback_endpoint = "https://api.mystore.com/authenticate"
  authentication_callback_api_key = "lkjl3k44235kjlk5j43kjdkfslkdf"
  authentication_callback_api_secret = "lknasdljjk42j435kjh34jkkjr"
  supported_acrs = ["loa2", "loa3"]
  developer_authentication_callback_endpoint = "https://api.mystore.com/partner_auth"
  developer_authentication_callback_api_key = "lkjl3k44235kjlk5j43kjdkfslkdf"
  developer_authentication_callback_api_secret = "lknasdljjk42j435kjh34jkkjr"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  supported_authorization_detail_types = ["payment_initiation",]
  supported_service_profiles = ["FAPI", "OPEN_BANKING",]
  error_description_omitted = true
  error_uri_omitted = false
  authorization_endpoint = "https://www.mystore.com/authorize"
  direct_authorization_endpoint_enabled = false
  supported_ui_locales = ["fr-CA","fr", "en-GB", "en"]
  supported_displays = [ "PAGE", "POPUP" ]
  pkce_required = false
  pkce_s256_required = true
  authorization_response_duration = 10
  iss_response_suppressed = true
  ignore_port_loopback_redirect = true
  token_endpoint = "https://api.mystore.com/token"
  direct_token_endpoint_enabled = false
  supported_token_auth_methods = ["CLIENT_SECRET_POST", "TLS_CLIENT_AUTH"]
  mutual_tls_validate_pki_cert_chain = true
  trusted_root_certificates = ["-----BEGIN CERTIFICATE-----\r\nMIIDpjCCAo6gAwIBAgIUS3mWeRx1uG/SMl/ql55VwRtNz7wwDQYJKoZIhvcNAQEL\r\nBQAwazELMAkGA1UEBhMCQlIxHDAaBgNVBAoTE09wZW4gQmFua2luZyBCcmFzaWwx\r\nFTATBgNVBAsTDE9wZW4gQmFua2luZzEnMCUGA1UEAxMeT3BlbiBCYW5raW5nIFJv\r\nb3QgU0FOREJPWCAtIEcxMB4XDTIwMTIxMTEwMDAwMFoXDTI1MTIxMDEwMDAwMFow\r\nazELMAkGA1UEBhMCQlIxHDAaBgNVBAoTE09wZW4gQmFua2luZyBCcmFzaWwxFTAT\r\nBgNVBAsTDE9wZW4gQmFua2luZzEnMCUGA1UEAxMeT3BlbiBCYW5raW5nIFJvb3Qg\r\nU0FOREJPWCAtIEcxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp50j\r\njNh0wu8ioziC1HuWqOfgXwxeiePiRGw5tKDqKIbC7XV1ghEcDiymTHHWWJSQ1LEs\r\nmYpZVwaos5Mrz2xJwytg8K5eqFqa7QvfOOul29bnzEFk+1gX/0nOYws3Lba9E7S+\r\nuPaUmfElF4r2lcCNL2f3F87RozqZf+DQBdGUzAt9n+ipY1JpqfI3KF/5qgRkPoIf\r\nJD+aj2Y1D6eYjs5uMRLU8FMYt0CCfv/Ak6mq4Y9/7CaMKp5qjlrrDux00IDpxoXG\r\nKx5cK0KgACb2UBZ98oDQxcGrbRIyp8VGmv68BkEQcm7NljP863uBVxtnVTpRwQ1x\r\nwYEbmSSyoonXy575wQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/\r\nBAUwAwEB/zAdBgNVHQ4EFgQUhxPslj5i7CEcDEpWOvIlDOOU6cswDQYJKoZIhvcN\r\nAQELBQADggEBAFoYqwoH7zvr4v0SQ/hWx/bWFRIcV/Rf6rEWGyT/moVAEjPbGH6t\r\nyHhbxh3RdGcPY7Pzn797lXDGRu0pHv+GAHUA1v1PewCp0IHYukmN5D8+Qumem6by\r\nHyONyUASMlY0lUOzx9mHVBMuj6u6kvn9xjL6xsPS+Cglv/3SUXUR0mMCYf963xnF\r\nBIRLTRlbykgJomUptVl/F5U/+8cD+lB/fcZPoQVI0kK0VV51jAODSIhS6vqzQzH4\r\ncpUmcPh4dy+7RzdTTktxOTXTqAy9/Yx+fk18O9qSQw1MKa9dDZ4YLnAQS2fJJqIE\r\n1DXIta0LpqM4pMoRMXvp9SLU0atVZLEu6Sc=\r\n-----END CERTIFICATE-----"]
  missing_client_id_allowed = true
  revocation_endpoint = "https://api.mystore.com/revoke"
  direct_revocation_endpoint_enabled = true
  supported_revocation_auth_methods = ["CLIENT_SECRET_POST", "TLS_CLIENT_AUTH"]
  pushed_auth_req_endpoint = "https://api.mystore.com/pushed"
  pushed_auth_req_duration = 10
  par_required = true
  request_object_required = true
  traditional_request_object_processing_applied = true
  nbf_optional = false
  front_channel_encryption_request_obj_required = true
  encryption_alg_req_obj_match = true
  encryption_enc_alg_req_obj_match = true
  access_token_type = "Bearer"
  tls_client_certificate_bound_access_tokens = true
  access_token_duration = 99
  single_access_token_per_subject = false
  access_token_sign_alg = "PS256"
  access_token_signature_key_id = "kid1"
  refresh_token_duration = 150
  refresh_token_duration_kept = false
  refresh_token_duration_reset = false
  refresh_token_kept = true
  token_expiration_link = true
  supported_scopes {
	name = "address"
    default_entry = false
    description = "A permission to request an OpenID Provider to include the address claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details."
  }
  supported_scopes {
	name = "email"
    default_entry = true
    description = "A permission to request an OpenID Provider to include the email claim and the email_verified claim in an ID Token. See OpenID Connect Core 1.0, 5.4. for details."
    attribute {
		key = "key1"
        value = "val1"
	}
  }
  scope_required = true
  id_token_duration = 98
  allowable_clock_skew = 1
  supported_claim_types = ["NORMAL", "AGGREGATED", "DISTRIBUTED"]
  supported_claim_locales = ["en", "fr", "jp"]
  supported_claims = ["name","email", "profile", "gender"]
  claim_shortcut_restrictive = true
  jwks_endpoint = "https://www.mystore.com/jwks"
  direct_jwks_endpoint_enabled = true
  jwk {
	  kid = "kid1"
	  alg = "RS256" 
	  use = "sig" 
	  kty = "RSA"
   key_size = 2048
      generate = true
   }
  jwk {
	  kid = "kid2"
	  alg = "RS256" 
	  use = "sig" 
   key_size = 2048
	  kty = "RSA"
      generate = true
   }
  id_token_signature_key_id = "kid1"
  user_info_signature_key_id = "kid1"
  authorization_signature_key_id = "kid2"
  hsm_enabled = false
  user_info_endpoint = "https://api.mystore.com/userinfo"
  direct_user_info_endpoint_enabled = false
  dcr_scope_used_as_requestable = true
  registration_endpoint = "https://api.mystore.com/dcr"
  registration_management_endpoint = "https://api.mystore.com/client/"
  mtls_endpoint_aliases {
	name = "test"
    uri = "https://test.com"
  }
  policy_uri = "https://www.mystore.com/policy"
  tos_uri = "https://www.mystore.com/tos"
  service_documentation= "https://www.mystore.com/doc"
  backchannel_authentication_endpoint = "https://api.mystore.com/ciba"
  supported_backchannel_token_delivery_modes = [ "POLL"]
  backchannel_auth_req_id_duration = 15
  backchannel_polling_interval = 3
  backchannel_user_code_parameter_supported = true
  backchannel_binding_message_required_in_fapi = true
  device_authorization_endpoint = "https://api.mystore.com/device"
  device_verification_uri= "https://api.mystore.com/devverify"
  device_verification_uri_complete= "https://example.com/verification?user_code=USER_CODE"
  device_flow_code_duration = 10
  device_flow_polling_interval = 1
  user_code_charset = "NUMERIC"
  user_code_length= 6
  #supported_trust_frameworks = ["eidas_ial_high"]
  #supported_evidence = ["id_document", "utility_bill"]
  #supported_identity_documents = ["idcard", "password"]
  #supported_verification_methods= ["pipp"]
  #supported_verified_claims = ["given_name"]
  end_session_endpoint = "https://www.mystore.com/endsession"
  dcr_duplicate_software_id_blocked = true
}

output "api_key" {  
  value = authlete_service.complete_described.id
}
output "api_secret" {  
  value = authlete_service.complete_described.api_secret
}
`

const testAccResourceServiceUnordered = `
provider "authlete" {
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Simplest Test API"
  supported_grant_types = ["REFRESH_TOKEN", "AUTHORIZATION_CODE" ]
  supported_response_types = ["CODE"]

  supported_scopes {
    name = "test2"
  }
  supported_scopes {
    name = "test1"
  }
}

output "api_key" {  
  value = authlete_service.prod.id
}
output "api_secret" {  
  value = authlete_service.prod.api_secret
}
`

// Scenarios for crypto tests

const testAccGenerateRSAKeys = `
provider "authlete" {
	
}

resource "authlete_service" "rsa" {
  issuer = "https://test.com"
  service_name = "RSA Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "RS256"
  access_token_signature_key_id = "rsa1"
  jwk {
	  kid = "rsa1"
	  alg = "RS256" 
	  use = "sig" 
	  kty = "RSA"
      key_size = 2048
      generate = true
   }
   jwk {
	  kid = "rsa2"
	  alg = "RS384" 
	  use = "sig" 
	  kty = "RSA"
      key_size = 2048
      generate = true
   }
   jwk {
	  kid = "rsa3"
	  alg = "RS512" 
	  use = "sig" 
	  kty = "RSA"
      key_size = 2048
      generate = true
   }
   jwk {
	kid = "psa1"
	alg = "PS256" 
	use = "sig"
 	key_size = 2048
    generate = true
   } 
   jwk {
	kid = "psa2"
	alg = "PS384" 
	use = "sig"
 	key_size = 2048
    generate = true
   } 
   jwk {
	kid = "psa3"
	alg = "PS512" 
	use = "sig"
 	key_size = 2048
    generate = true
   } 
   jwk {
	kid = "encrsa1"
	alg = "RSA-OAEP" 
	use = "enc"
 	key_size = 2048
    generate = true
   } 
   jwk {
	kid = "encrsa2"
	alg = "RSA-OAEP-256" 
	use = "enc" 
 	key_size = 2048
	generate = true
   }
   jwk {
	kid = "encrsa3"
	alg = "RSA-OAEP-256" 
	use = "enc" 
    key_size = 4096
	generate = true
   }
}
`

const testAccGenerateRSAKeysCreate = `
provider "authlete" {
	
}

resource "authlete_service" "rsa" {
  issuer = "https://test.com"
  service_name = "RSA Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "RS256"
  access_token_signature_key_id = "rsa1"
   jwk {
	  kid = "rsa1"
	  alg = "RS384" 
	  use = "sig" 
	  kty = "RSA"
      key_size = 2048
      generate = true
   }
   jwk {
	  kid = "rsa2"
	  alg = "RS384" 
	  use = "sig" 
	  kty = "RSA"
      key_size = 2048
      generate = true
   }
}
`

const testAccGenerateRSAKeysUpdate = `
provider "authlete" {
	
}

resource "authlete_service" "rsa" {
  issuer = "https://test.com"
  service_name = "RSA Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "RS256"
  access_token_signature_key_id = "rsa2"
   jwk {
	  kid = "rsa2"
	  alg = "RS384" 
	  use = "sig" 
	  kty = "RSA"
      key_size = 2048
      generate = true
   }
   jwk {
	  kid = "rsa3"
	  alg = "RS384" 
	  use = "sig" 
	  kty = "RSA"
      key_size = 2048
      generate = true
   }
}
`

const testAccGenerateECKeys = `

provider "authlete" {
	
}

resource "authlete_service" "ec" {
  issuer = "https://test.com"
  service_name = "EC Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "ES256"
  access_token_signature_key_id = "ec1"
  jwk {
	  kid = "ec1"
	  alg = "ES256" 
	  use = "sig"
      crv = "P-256"
      generate = true
   }
  jwk {
	  kid = "ec3"
	  alg = "ES384" 
	  use = "sig"
      crv = "P-256"
      generate = true
   }
  jwk {
	  kid = "ec4"
	  alg = "ES512" 
	  use = "sig"
      crv = "P-256"
      generate = true
   }
   jwk {
	  kid = "enc1"
	  alg = "ECDH-ES" 
	  use = "enc"
      crv = "P-256"
      generate = true
   }
   jwk {
	  kid = "enc2"
	  alg = "ECDH-ES+A128KW" 
	  use = "enc"
      crv = "P-256"
      generate = true
   }
   jwk {
	kid = "enc3"
	alg = "ECDH-ES+A192KW" 
	use = "enc"
      crv = "P-256"
    generate = true
   }
}
`

const testAccGenerateECKeysCreate = `

provider "authlete" {
	
}

resource "authlete_service" "ec" {
  issuer = "https://test.com"
  service_name = "EC Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "ES256"
  access_token_signature_key_id = "ec1"
  jwk {
	  kid = "ec1"
	  alg = "ES256" 
      crv = "P-256"
	  use = "sig"
      generate = true
   }
   jwk {
	  kid = "ec2"
	  alg = "ES256" 
      crv = "P-256"
	  use = "sig"
      generate = true
   }
   jwk {
	  kid = "enc1"
	  alg = "ECDH-ES" 
	  use = "enc"
      crv = "P-256"
      generate = true
   }
   jwk {
	  kid = "enc2"
	  alg = "ECDH-ES+A128KW" 
	  use = "enc"
      crv = "P-256"
      generate = true
   }
}
`

const testAccGenerateECKeysUpdate = `

provider "authlete" {
	
}

resource "authlete_service" "ec" {
  issuer = "https://test.com"
  service_name = "EC Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "ES256"
  access_token_signature_key_id = "ec2"
   jwk {
	  kid = "ec2"
	  alg = "ES256" 
	  use = "sig"
      crv = "P-256"
      generate = true
   }
   jwk {
	  kid = "ec3"
	  alg = "ES256" 
	  use = "sig"
      crv = "P-256"
      generate = true
   }
   jwk {
	  kid = "enc2"
	  alg = "ECDH-ES+A128KW" 
	  use = "enc"
      crv = "P-256"
      generate = true
   }
   jwk {
	  kid = "enc3"
	  alg = "ECDH-ES" 
	  use = "enc"
      crv = "P-256"
      generate = true
   }
   
}
`

const testAccGenerateRSAKeysImport = `
provider "authlete" {
	
}

resource "authlete_service" "import" {
  issuer = "https://test.com"
  service_name = "RSA Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "RS256"
  access_token_signature_key_id = "rsa1"
   jwk {
	  kid = "rsa1"
	  alg = "PS256" 
	  use = "sig" 
	  kty = "RSA"
      generate = false
		p = "9tbn_sEgxi3hkTlKfYegMLJsTn_6EPK3XdRJbJINIlH6sCGKKkxEs76aehNw2E08xbJE8Np3v4PdAnBkZkaMIWT8JxQxv_TS_TBqMNdO886PIM-fWitV3QUf2nzinYHf-_PXdZnqpd4S4x9Xe0pYMpb2g83X8NuevRu_HzxL8bM"
 		q = "nRzgvjEqLQRFzYX1ZqtJYB6L8MyhuEucOCHSr-fDVGBlM2iMTsgAG5icnz9BfwUK4_lBsxdYM938GcmrwT6ZE4ANKS9t1BZamctqZGKf4sY_QvjEkDV4DHvnUV2i_tsVvwDPaUvUT_8lU73Y08N7BVLhcY3wEJf9NKofbCONU_M"
    	d = "EVpIBBlbOksB2eiQ4Mt_lAlkuGYzhRjbP2v4mIxcpXO6r5OZgCcodoQTQKTLKx4zhzm6L3xb75BZNDrdu481EvcdJm1mXwhIi9B8DheOD3Y1rzrreulM_4yS1EJQjpIjwmXHiV9nK6qSM8FNFe98FGFA9X7dghBeAQm1ZmGdp-zzK4EMLvbSqMY1yK9GQ52TpvWW26V_V885zWZKbSoIOdLJ8cr_OwSAXp1wezpnscTwoqw1iwZAP1m9fehmLBKEOxUMOSpjbl53AjVVWvGX3ShV1JPnFeMb3zhWzt2_LdqJTWONSWS-zhNSsWDWdnYQTBb7Xz0HGdlegAuDxF1aDQ"
    	e = "AQAB"
       qi = "9YboaIGrL8wY9JNvbkJ0-6D4sUZEMWuBJTD7mmTUeIy94hlNNZDdcgQo8hzOcOVXkjrrVKxsRekU05rg_XNLaODC2_au36VduYWQ1RM70OQ-kfk4zYJK63C8OFseh-9K4Teu82We7858yN4P-GvPeZYMvDlTagbGDUYKm7DTrgA"
       dp = "RmXmRnbIJR1CvstLHmAG5LyOPRkstZazizQXOLqyuj4NNBxsrkGQOn86yWQwA9CLa4q7NMHp8xnld2OcjrrCDmghrfeJdMibQBCFyKYvY0Ne-KmeNfY0B9QFUKfbbbZzrgTOR0D9dg7O7i2rIoOCgfMiHVcgphXMwPxf1sW4lxc"
       dq = "BykoySJehLy8HbjsTWijKIFb6Xa6LDcuAJTyEFhk27SlCCnMs06ESr2y7cMpTgvBylAzAWGgAIUul1JMxLsAqRXeA7GItPDr4jSWPcsM9H4KphfGhbgaJ5-CFIBLDIiZviHgUjFFlPvRDLcLaeNv-PclFVLdzTPQM5VJZ1lbeKc"
        n = "l32kfAo1HkGMSmx4OFk45klYE736CttrvHPPLzHuZbQYQbBxniaxLiheR_SsAUY8rl6lTBlaDzgOEc2qNxJm_hAIGbs13GucJ3TchR51NRrx9xYFCpBh9-_8NYKaPLl0iwzaoUOS1-wDFIvYR6Hy1Qsg7voz7yZMXflUvsxn24nIWQE7zfDXSYJFB-v__OPhPvSO3bj6BOKGq85JIVYnpQHc8Yy835tfbGt7a_ZExrCkGSgvxMqSawVeXyltIyk9rd6g_VxrLomtPahw0LpiLzDFr2s8YpWRdxPbp2N6CxtIB_LFAzXyhB3hSww5V28fTCI2kW_DNk-I7MeWdAp16Q"
   }

	jwk {
		kid = "ec1"
		crv = "P-256"
    	kty = "EC"
    	  d = "VT0W-vHxG8Wc0Ev0UT1jIs0XKfctQfQc93WV5Bqb2a0"
    	use = "sig"
    	  x = "coUEzc60fSaVWui-NCUEqAKwFq_isrQbdcxk-jafyTw"
          y = "b9hCE1LgOry4mEUFgfz49NBEiNuC5mbBgb9glVZp420"
		alg = "ES256"
    }
}
`

const rsaPrivateKeyPem = "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEA71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0\r\nYPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+rMmBV0iNv4y289eEZa5Ipvk9T\r\nFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTboHYadJ5l/rjpRSNxE7i7b34Bi\r\n1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw/5fF+HDBGcB4u7Fm6fK6T4C3\r\n7ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2Jt+DnxNCNqBa0ezLY70g0no6\r\nYkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQIDAQABAoIBAQCoSBWdibrZIJ/R\r\nZjLxDlKdw4JXxj5o5DkxtxPBaCHknmeffCdO+r959CIbBd6R1w+GIjShDP9RIcQ4\r\nbA+GJC1j+CuG62fMrvAgO+vOs20NTyOc1efldkBstiKd6sKEgJOMZmp3KgcSUc8s\r\n+lh0CoPYbGf/QsTDsFGvrv+yjHbHRb1bcQjNZCE77Vr9SvdVFOph8750DvftwHdy\r\nvZKe9u3VjcC0LGA1qFZeUgwfynNaGcxwiZ/gZ2vnAbAW+g7YpfdqTs4l32yQAluw\r\n3Ctg1pYtzz4M1iX4OyX5LWMS/P/1Xr9fXLGS0H8EYoACb+mb5LOTR6xWHQZpfo7A\r\nmTErM6lxAoGBAPwyn//oh7XY32BGoGGofkUhoD5p7c+OUKjHpSysH6AP31ZYAA3N\r\nY5hsRCY9hHsF08EWpdfN+i6oPTTYATb8hXJ+5MotrehsitnubjkE5uuym5sXf040\r\nDorD0/oH2WyICenNryyWqx1uRAJlmrZoBe5dJ4hEzkv6pAwMu3HgyTZtAoGBAPLw\r\nx0ZEr32gTbGSpNvxHUfwZY2qtuG9CLQ3MR8JwkkK91RqOKiB2LLjP7LoiWE4BLF9\r\nCsLT4MDDXcWMcGCsQ8bTbapPgdE1uuGAyzpuigQMn/FwNLjHnaJlpvX5EZT9AauS\r\nNkNV/EGojIhXsJ3sfyU6qRoeeOkmobzqDybe5wLVAoGAT8u01EO+rMrx4oR2OnAV\r\ng8of6Z+anxFoc/63RGsxlnNvNuKhIbzaxl97MJ5GTKaLWYzQ7Hc/sYOJ2i5+M+ey\r\nUYfU3COX4vJ0/H90YJYsemcI1QmaPiQ6da2AZJwXLz/b4x4xTupdOfKpkhiT2yMO\r\nvVy8JWGf5GppfWaJ6H43LAECgYBc+xCZ8VHlWAREcWbNkzPsw7JqjSsfrNT2/KS9\r\nR2Pnxt2wnlL/E2tX1CgeFmf2IJWTRNNoi+VagauTH1Qne+cY4vT3GSULaHAVPNEL\r\nlSEXualBo/tZuXS4ogVL4T78cfVAsF46WV+J1bOrvzwmxUxIeHIeQAlw2stOXZrc\r\n+rUZ3QKBgQD3XGwp6Q72wC/b54oHFQSF4dQUelDPiSahljkWm6NRgqxK9NDw7Npn\r\nVLeGgVfA8Z3tvpXSggJmEA1VNt89NKrjzDrcvcxTzHV/gImNyBpisfsVHQrdghob\r\nfzXxPz3vVIjMLGEYpWumd/nnReWuhcC2rUdo/S0Wc7+CABs7B3UdZg==\r\n-----END RSA PRIVATE KEY-----"
const rsaCertWithoutChain = "-----BEGIN CERTIFICATE-----\r\nMIIEwTCCAqmgAwIBAgIID+K+XgJff98wDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\r\nBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhB\r\ndXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcwNjE5NTEwMFoXDTIzMDcw\r\nNjE5NTEwMFowUzELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdW\r\naXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTESMBAGA1UEAwwJc2VydmVyX29wMIIB\r\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA71UPBn2cS7qP89sdIlWEv2Kr\r\nsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+r\r\nMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTbo\r\nHYadJ5l/rjpRSNxE7i7b34Bi1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw\r\n/5fF+HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2\r\nJt+DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQID\r\nAQABo4GbMIGYMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGrTFrTNXRXUDJwCxueM\r\nIhznWSw9MAsGA1UdDwQEAwID6DATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREE\r\nDTALgglzZXJ2ZXJfb3AwEQYJYIZIAYb4QgEBBAQDAgZAMB4GCWCGSAGG+EIBDQQR\r\nFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACBKbO/kmaQ2HGxj\r\nmy4Vnap5D45ydgOVzFy1juw/QhyyX+Cth71CONt/39tJlE12vJcqcZxV1JMnY3JI\r\n5rrX62YxuczCrU5W2+Xn5Jo7lY0mFvGbi89bXQruHIDMnLpyXw4Ri5UkaMTuG/cr\r\nAj26pMGnCcWFhos7knKQQ4Yu2zwYymhNWlVAbNxTPvM5fcTHSNB2nxU/Q8UqOIzF\r\nAKL1iCBPlF3BDaLijQxA6aGYzouiefnzy3ODjOuIy3qM4yfD1gh9jHrRs+h+TJZ3\r\nPQ4xZfBkgVMkQcOcsjWEOZf+uXQTVMHF7Y4c41u8VG3IljLCS0ipD86nLq9wbTYR\r\nlA3to3IRCj9PwGCZIUALqmmmgRnw834P90mp8GsLtTbVTGO/zLRI46MHeeLiJmea\r\nHVItOpqn5ahpiauqrdXpoGTlecqmfAkyREn64xkTwGqDqL5X0NMIXre+7ydZb56P\r\npZFb8CBviEGmTW6hYvsqHp7E3phPoOs72zww1jTipCC43DrGbYk/FoBjj6SORHpE\r\n456Zaj7rboJortVwkI8uwzg799wimTWvz2kGQT4+zDvQMa38XrEuAO8fhqf+2I9Q\r\nSSLrHMO4MyflFnuLf8KLC3ochRzCJDbkB9K8s/DiELK3pj7NZXwUzT5pxF3n5oZD\r\nm/0k4YruLQ7bFY+/xjRBH+741916\r\n-----END CERTIFICATE-----"
const rsaCertChain = "Bag Attributes\r\n    friendlyName: server_op\r\n    localKeyID: 49 94 37 79 51 B9 AA A2 20 59 8C 1B 6F 9A F3 40 31 16 03 8B\r\nsubject=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=server_op\r\nissuer=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=rsa_ca\r\n-----BEGIN CERTIFICATE-----\r\nMIIEwTCCAqmgAwIBAgIID+K+XgJff98wDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\r\nBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhB\r\ndXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcwNjE5NTEwMFoXDTIzMDcw\r\nNjE5NTEwMFowUzELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdW\r\naXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTESMBAGA1UEAwwJc2VydmVyX29wMIIB\r\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA71UPBn2cS7qP89sdIlWEv2Kr\r\nsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+r\r\nMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTbo\r\nHYadJ5l/rjpRSNxE7i7b34Bi1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw\r\n/5fF+HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2\r\nJt+DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQID\r\nAQABo4GbMIGYMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGrTFrTNXRXUDJwCxueM\r\nIhznWSw9MAsGA1UdDwQEAwID6DATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREE\r\nDTALgglzZXJ2ZXJfb3AwEQYJYIZIAYb4QgEBBAQDAgZAMB4GCWCGSAGG+EIBDQQR\r\nFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACBKbO/kmaQ2HGxj\r\nmy4Vnap5D45ydgOVzFy1juw/QhyyX+Cth71CONt/39tJlE12vJcqcZxV1JMnY3JI\r\n5rrX62YxuczCrU5W2+Xn5Jo7lY0mFvGbi89bXQruHIDMnLpyXw4Ri5UkaMTuG/cr\r\nAj26pMGnCcWFhos7knKQQ4Yu2zwYymhNWlVAbNxTPvM5fcTHSNB2nxU/Q8UqOIzF\r\nAKL1iCBPlF3BDaLijQxA6aGYzouiefnzy3ODjOuIy3qM4yfD1gh9jHrRs+h+TJZ3\r\nPQ4xZfBkgVMkQcOcsjWEOZf+uXQTVMHF7Y4c41u8VG3IljLCS0ipD86nLq9wbTYR\r\nlA3to3IRCj9PwGCZIUALqmmmgRnw834P90mp8GsLtTbVTGO/zLRI46MHeeLiJmea\r\nHVItOpqn5ahpiauqrdXpoGTlecqmfAkyREn64xkTwGqDqL5X0NMIXre+7ydZb56P\r\npZFb8CBviEGmTW6hYvsqHp7E3phPoOs72zww1jTipCC43DrGbYk/FoBjj6SORHpE\r\n456Zaj7rboJortVwkI8uwzg799wimTWvz2kGQT4+zDvQMa38XrEuAO8fhqf+2I9Q\r\nSSLrHMO4MyflFnuLf8KLC3ochRzCJDbkB9K8s/DiELK3pj7NZXwUzT5pxF3n5oZD\r\nm/0k4YruLQ7bFY+/xjRBH+741916\r\n-----END CERTIFICATE-----\r\nBag Attributes: <No Attributes>\r\nsubject=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=rsa_ca\r\nissuer=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=rsa_ca\r\n-----BEGIN CERTIFICATE-----\r\n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\r\n-----END CERTIFICATE-----\r\nBag Attributes\r\n    friendlyName: server_op\r\n    localKeyID: 49 94 37 79 51 B9 AA A2 20 59 8C 1B 6F 9A F3 40 31 16 03 8B\r\nKey Attributes: <No Attributes>\r\n"

var testAccPemRSASupport = `
provider "authlete" {
	
}

resource "authlete_service" "rsa" {
  issuer = "https://test.com"
  service_name = "RSA Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "RS256"
  access_token_signature_key_id = "rsa1"
  jwk {
	  kid = "rsa1"
	  alg = "RS256" 
	  use = "sig" 
	  pem_private_key = "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEA71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0\r\nYPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+rMmBV0iNv4y289eEZa5Ipvk9T\r\nFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTboHYadJ5l/rjpRSNxE7i7b34Bi\r\n1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw/5fF+HDBGcB4u7Fm6fK6T4C3\r\n7ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2Jt+DnxNCNqBa0ezLY70g0no6\r\nYkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQIDAQABAoIBAQCoSBWdibrZIJ/R\r\nZjLxDlKdw4JXxj5o5DkxtxPBaCHknmeffCdO+r959CIbBd6R1w+GIjShDP9RIcQ4\r\nbA+GJC1j+CuG62fMrvAgO+vOs20NTyOc1efldkBstiKd6sKEgJOMZmp3KgcSUc8s\r\n+lh0CoPYbGf/QsTDsFGvrv+yjHbHRb1bcQjNZCE77Vr9SvdVFOph8750DvftwHdy\r\nvZKe9u3VjcC0LGA1qFZeUgwfynNaGcxwiZ/gZ2vnAbAW+g7YpfdqTs4l32yQAluw\r\n3Ctg1pYtzz4M1iX4OyX5LWMS/P/1Xr9fXLGS0H8EYoACb+mb5LOTR6xWHQZpfo7A\r\nmTErM6lxAoGBAPwyn//oh7XY32BGoGGofkUhoD5p7c+OUKjHpSysH6AP31ZYAA3N\r\nY5hsRCY9hHsF08EWpdfN+i6oPTTYATb8hXJ+5MotrehsitnubjkE5uuym5sXf040\r\nDorD0/oH2WyICenNryyWqx1uRAJlmrZoBe5dJ4hEzkv6pAwMu3HgyTZtAoGBAPLw\r\nx0ZEr32gTbGSpNvxHUfwZY2qtuG9CLQ3MR8JwkkK91RqOKiB2LLjP7LoiWE4BLF9\r\nCsLT4MDDXcWMcGCsQ8bTbapPgdE1uuGAyzpuigQMn/FwNLjHnaJlpvX5EZT9AauS\r\nNkNV/EGojIhXsJ3sfyU6qRoeeOkmobzqDybe5wLVAoGAT8u01EO+rMrx4oR2OnAV\r\ng8of6Z+anxFoc/63RGsxlnNvNuKhIbzaxl97MJ5GTKaLWYzQ7Hc/sYOJ2i5+M+ey\r\nUYfU3COX4vJ0/H90YJYsemcI1QmaPiQ6da2AZJwXLz/b4x4xTupdOfKpkhiT2yMO\r\nvVy8JWGf5GppfWaJ6H43LAECgYBc+xCZ8VHlWAREcWbNkzPsw7JqjSsfrNT2/KS9\r\nR2Pnxt2wnlL/E2tX1CgeFmf2IJWTRNNoi+VagauTH1Qne+cY4vT3GSULaHAVPNEL\r\nlSEXualBo/tZuXS4ogVL4T78cfVAsF46WV+J1bOrvzwmxUxIeHIeQAlw2stOXZrc\r\n+rUZ3QKBgQD3XGwp6Q72wC/b54oHFQSF4dQUelDPiSahljkWm6NRgqxK9NDw7Npn\r\nVLeGgVfA8Z3tvpXSggJmEA1VNt89NKrjzDrcvcxTzHV/gImNyBpisfsVHQrdghob\r\nfzXxPz3vVIjMLGEYpWumd/nnReWuhcC2rUdo/S0Wc7+CABs7B3UdZg==\r\n-----END RSA PRIVATE KEY-----"
  }
  jwk {
	  kid = "rsa2"
	  alg = "RS256" 
	  use = "sig" 
	  pem_private_key = "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEA71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0\r\nYPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+rMmBV0iNv4y289eEZa5Ipvk9T\r\nFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTboHYadJ5l/rjpRSNxE7i7b34Bi\r\n1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw/5fF+HDBGcB4u7Fm6fK6T4C3\r\n7ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2Jt+DnxNCNqBa0ezLY70g0no6\r\nYkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQIDAQABAoIBAQCoSBWdibrZIJ/R\r\nZjLxDlKdw4JXxj5o5DkxtxPBaCHknmeffCdO+r959CIbBd6R1w+GIjShDP9RIcQ4\r\nbA+GJC1j+CuG62fMrvAgO+vOs20NTyOc1efldkBstiKd6sKEgJOMZmp3KgcSUc8s\r\n+lh0CoPYbGf/QsTDsFGvrv+yjHbHRb1bcQjNZCE77Vr9SvdVFOph8750DvftwHdy\r\nvZKe9u3VjcC0LGA1qFZeUgwfynNaGcxwiZ/gZ2vnAbAW+g7YpfdqTs4l32yQAluw\r\n3Ctg1pYtzz4M1iX4OyX5LWMS/P/1Xr9fXLGS0H8EYoACb+mb5LOTR6xWHQZpfo7A\r\nmTErM6lxAoGBAPwyn//oh7XY32BGoGGofkUhoD5p7c+OUKjHpSysH6AP31ZYAA3N\r\nY5hsRCY9hHsF08EWpdfN+i6oPTTYATb8hXJ+5MotrehsitnubjkE5uuym5sXf040\r\nDorD0/oH2WyICenNryyWqx1uRAJlmrZoBe5dJ4hEzkv6pAwMu3HgyTZtAoGBAPLw\r\nx0ZEr32gTbGSpNvxHUfwZY2qtuG9CLQ3MR8JwkkK91RqOKiB2LLjP7LoiWE4BLF9\r\nCsLT4MDDXcWMcGCsQ8bTbapPgdE1uuGAyzpuigQMn/FwNLjHnaJlpvX5EZT9AauS\r\nNkNV/EGojIhXsJ3sfyU6qRoeeOkmobzqDybe5wLVAoGAT8u01EO+rMrx4oR2OnAV\r\ng8of6Z+anxFoc/63RGsxlnNvNuKhIbzaxl97MJ5GTKaLWYzQ7Hc/sYOJ2i5+M+ey\r\nUYfU3COX4vJ0/H90YJYsemcI1QmaPiQ6da2AZJwXLz/b4x4xTupdOfKpkhiT2yMO\r\nvVy8JWGf5GppfWaJ6H43LAECgYBc+xCZ8VHlWAREcWbNkzPsw7JqjSsfrNT2/KS9\r\nR2Pnxt2wnlL/E2tX1CgeFmf2IJWTRNNoi+VagauTH1Qne+cY4vT3GSULaHAVPNEL\r\nlSEXualBo/tZuXS4ogVL4T78cfVAsF46WV+J1bOrvzwmxUxIeHIeQAlw2stOXZrc\r\n+rUZ3QKBgQD3XGwp6Q72wC/b54oHFQSF4dQUelDPiSahljkWm6NRgqxK9NDw7Npn\r\nVLeGgVfA8Z3tvpXSggJmEA1VNt89NKrjzDrcvcxTzHV/gImNyBpisfsVHQrdghob\r\nfzXxPz3vVIjMLGEYpWumd/nnReWuhcC2rUdo/S0Wc7+CABs7B3UdZg==\r\n-----END RSA PRIVATE KEY-----"
      pem_certificate = "-----BEGIN CERTIFICATE-----\r\nMIIEwTCCAqmgAwIBAgIID+K+XgJff98wDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\r\nBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhB\r\ndXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcwNjE5NTEwMFoXDTIzMDcw\r\nNjE5NTEwMFowUzELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdW\r\naXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTESMBAGA1UEAwwJc2VydmVyX29wMIIB\r\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA71UPBn2cS7qP89sdIlWEv2Kr\r\nsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+r\r\nMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTbo\r\nHYadJ5l/rjpRSNxE7i7b34Bi1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw\r\n/5fF+HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2\r\nJt+DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQID\r\nAQABo4GbMIGYMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGrTFrTNXRXUDJwCxueM\r\nIhznWSw9MAsGA1UdDwQEAwID6DATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREE\r\nDTALgglzZXJ2ZXJfb3AwEQYJYIZIAYb4QgEBBAQDAgZAMB4GCWCGSAGG+EIBDQQR\r\nFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACBKbO/kmaQ2HGxj\r\nmy4Vnap5D45ydgOVzFy1juw/QhyyX+Cth71CONt/39tJlE12vJcqcZxV1JMnY3JI\r\n5rrX62YxuczCrU5W2+Xn5Jo7lY0mFvGbi89bXQruHIDMnLpyXw4Ri5UkaMTuG/cr\r\nAj26pMGnCcWFhos7knKQQ4Yu2zwYymhNWlVAbNxTPvM5fcTHSNB2nxU/Q8UqOIzF\r\nAKL1iCBPlF3BDaLijQxA6aGYzouiefnzy3ODjOuIy3qM4yfD1gh9jHrRs+h+TJZ3\r\nPQ4xZfBkgVMkQcOcsjWEOZf+uXQTVMHF7Y4c41u8VG3IljLCS0ipD86nLq9wbTYR\r\nlA3to3IRCj9PwGCZIUALqmmmgRnw834P90mp8GsLtTbVTGO/zLRI46MHeeLiJmea\r\nHVItOpqn5ahpiauqrdXpoGTlecqmfAkyREn64xkTwGqDqL5X0NMIXre+7ydZb56P\r\npZFb8CBviEGmTW6hYvsqHp7E3phPoOs72zww1jTipCC43DrGbYk/FoBjj6SORHpE\r\n456Zaj7rboJortVwkI8uwzg799wimTWvz2kGQT4+zDvQMa38XrEuAO8fhqf+2I9Q\r\nSSLrHMO4MyflFnuLf8KLC3ochRzCJDbkB9K8s/DiELK3pj7NZXwUzT5pxF3n5oZD\r\nm/0k4YruLQ7bFY+/xjRBH+741916\r\n-----END CERTIFICATE-----"
  }
  jwk {
	  kid = "rsa3"
	  alg = "RS256" 
	  use = "sig" 
	  pem_private_key = "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEA71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0\r\nYPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+rMmBV0iNv4y289eEZa5Ipvk9T\r\nFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTboHYadJ5l/rjpRSNxE7i7b34Bi\r\n1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw/5fF+HDBGcB4u7Fm6fK6T4C3\r\n7ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2Jt+DnxNCNqBa0ezLY70g0no6\r\nYkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQIDAQABAoIBAQCoSBWdibrZIJ/R\r\nZjLxDlKdw4JXxj5o5DkxtxPBaCHknmeffCdO+r959CIbBd6R1w+GIjShDP9RIcQ4\r\nbA+GJC1j+CuG62fMrvAgO+vOs20NTyOc1efldkBstiKd6sKEgJOMZmp3KgcSUc8s\r\n+lh0CoPYbGf/QsTDsFGvrv+yjHbHRb1bcQjNZCE77Vr9SvdVFOph8750DvftwHdy\r\nvZKe9u3VjcC0LGA1qFZeUgwfynNaGcxwiZ/gZ2vnAbAW+g7YpfdqTs4l32yQAluw\r\n3Ctg1pYtzz4M1iX4OyX5LWMS/P/1Xr9fXLGS0H8EYoACb+mb5LOTR6xWHQZpfo7A\r\nmTErM6lxAoGBAPwyn//oh7XY32BGoGGofkUhoD5p7c+OUKjHpSysH6AP31ZYAA3N\r\nY5hsRCY9hHsF08EWpdfN+i6oPTTYATb8hXJ+5MotrehsitnubjkE5uuym5sXf040\r\nDorD0/oH2WyICenNryyWqx1uRAJlmrZoBe5dJ4hEzkv6pAwMu3HgyTZtAoGBAPLw\r\nx0ZEr32gTbGSpNvxHUfwZY2qtuG9CLQ3MR8JwkkK91RqOKiB2LLjP7LoiWE4BLF9\r\nCsLT4MDDXcWMcGCsQ8bTbapPgdE1uuGAyzpuigQMn/FwNLjHnaJlpvX5EZT9AauS\r\nNkNV/EGojIhXsJ3sfyU6qRoeeOkmobzqDybe5wLVAoGAT8u01EO+rMrx4oR2OnAV\r\ng8of6Z+anxFoc/63RGsxlnNvNuKhIbzaxl97MJ5GTKaLWYzQ7Hc/sYOJ2i5+M+ey\r\nUYfU3COX4vJ0/H90YJYsemcI1QmaPiQ6da2AZJwXLz/b4x4xTupdOfKpkhiT2yMO\r\nvVy8JWGf5GppfWaJ6H43LAECgYBc+xCZ8VHlWAREcWbNkzPsw7JqjSsfrNT2/KS9\r\nR2Pnxt2wnlL/E2tX1CgeFmf2IJWTRNNoi+VagauTH1Qne+cY4vT3GSULaHAVPNEL\r\nlSEXualBo/tZuXS4ogVL4T78cfVAsF46WV+J1bOrvzwmxUxIeHIeQAlw2stOXZrc\r\n+rUZ3QKBgQD3XGwp6Q72wC/b54oHFQSF4dQUelDPiSahljkWm6NRgqxK9NDw7Npn\r\nVLeGgVfA8Z3tvpXSggJmEA1VNt89NKrjzDrcvcxTzHV/gImNyBpisfsVHQrdghob\r\nfzXxPz3vVIjMLGEYpWumd/nnReWuhcC2rUdo/S0Wc7+CABs7B3UdZg==\r\n-----END RSA PRIVATE KEY-----"
      pem_certificate = "Bag Attributes\r\n    friendlyName: server_op\r\n    localKeyID: 49 94 37 79 51 B9 AA A2 20 59 8C 1B 6F 9A F3 40 31 16 03 8B\r\nsubject=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=server_op\r\nissuer=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=rsa_ca\r\n-----BEGIN CERTIFICATE-----\r\nMIIEwTCCAqmgAwIBAgIID+K+XgJff98wDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\r\nBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhB\r\ndXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcwNjE5NTEwMFoXDTIzMDcw\r\nNjE5NTEwMFowUzELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdW\r\naXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTESMBAGA1UEAwwJc2VydmVyX29wMIIB\r\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA71UPBn2cS7qP89sdIlWEv2Kr\r\nsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+r\r\nMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTbo\r\nHYadJ5l/rjpRSNxE7i7b34Bi1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw\r\n/5fF+HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2\r\nJt+DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQID\r\nAQABo4GbMIGYMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGrTFrTNXRXUDJwCxueM\r\nIhznWSw9MAsGA1UdDwQEAwID6DATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREE\r\nDTALgglzZXJ2ZXJfb3AwEQYJYIZIAYb4QgEBBAQDAgZAMB4GCWCGSAGG+EIBDQQR\r\nFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACBKbO/kmaQ2HGxj\r\nmy4Vnap5D45ydgOVzFy1juw/QhyyX+Cth71CONt/39tJlE12vJcqcZxV1JMnY3JI\r\n5rrX62YxuczCrU5W2+Xn5Jo7lY0mFvGbi89bXQruHIDMnLpyXw4Ri5UkaMTuG/cr\r\nAj26pMGnCcWFhos7knKQQ4Yu2zwYymhNWlVAbNxTPvM5fcTHSNB2nxU/Q8UqOIzF\r\nAKL1iCBPlF3BDaLijQxA6aGYzouiefnzy3ODjOuIy3qM4yfD1gh9jHrRs+h+TJZ3\r\nPQ4xZfBkgVMkQcOcsjWEOZf+uXQTVMHF7Y4c41u8VG3IljLCS0ipD86nLq9wbTYR\r\nlA3to3IRCj9PwGCZIUALqmmmgRnw834P90mp8GsLtTbVTGO/zLRI46MHeeLiJmea\r\nHVItOpqn5ahpiauqrdXpoGTlecqmfAkyREn64xkTwGqDqL5X0NMIXre+7ydZb56P\r\npZFb8CBviEGmTW6hYvsqHp7E3phPoOs72zww1jTipCC43DrGbYk/FoBjj6SORHpE\r\n456Zaj7rboJortVwkI8uwzg799wimTWvz2kGQT4+zDvQMa38XrEuAO8fhqf+2I9Q\r\nSSLrHMO4MyflFnuLf8KLC3ochRzCJDbkB9K8s/DiELK3pj7NZXwUzT5pxF3n5oZD\r\nm/0k4YruLQ7bFY+/xjRBH+741916\r\n-----END CERTIFICATE-----\r\nBag Attributes: <No Attributes>\r\nsubject=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=rsa_ca\r\nissuer=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=rsa_ca\r\n-----BEGIN CERTIFICATE-----\r\nMIIFlDCCA3ygAwIBAgIIWkqSJb+GQMAwDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\r\nBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhB\r\ndXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcwNjE5NTAwMFoXDTMyMDcw\r\nNjE5NTAwMFowUDELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdW\r\naXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMIICIjAN\r\nBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0mI/8piFKm0/YROH2QbLesQYbqnA\r\nRCkQoXyvJNlGNK3Wf3+ZwZFsbUc+AGAIyN9l8x7UCXkGb1XJsX+EGWY2X8zIgARq\r\nBiCNAG1kpavkoQzzoygfsYjwlQbg7xxevjhXirsVxrLOhXTDC49DVVdldYCYgHqg\r\nrf8cb28/XVdc6qnau2T2wVPEpQmAfdQygsCcd0CBKFBt2ycDvQLnr3w5fnJ3SqjC\r\nb3i/Ji1n/fzWxc85ETp0Vg+8AHmpFoypiiPW0qzgUfHp4EhHg0At3PaHjrfYY2ac\r\n2j7+sziIFOyH4tmG4gd6Pwu8a4fRoFtJfAd0j581kus5oexnPPWszerJs0YATfel\r\nfxNE3s7xc3K5zRLRO9E5cRKUQ76eNKvl1hlTSHDm6RFRkXujB7xRNNoRW7nUCxds\r\nKZdThdjM5RbJuTeA49bk2kb3oJSEQdoQbISCoK9NXNNQ5rK8kBCPCI9aPr0Mq1w3\r\nROpHgZ+uME9Q15A4oLKkGPoQweiNYOdMujaV5zeMNzf+nFsSC5elwoFuZfa112Rw\r\nc2GbPL9ZJpYugfXxgpndpfK1IchMcqa5xOfuzFPeIdiTtJIs8GVGl7aiouAbVS34\r\n9/jdMT5mW84jYRwQtFYlwnYaUr7tsvTTc9MLybcwPnXlxhvx7jMX17iq5l1o1FDH\r\nZTnAnb4cBA1N6VcCAwEAAaNyMHAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU\r\neSxBE9pvc5+uF4OBjxRJFEXpPGUwCwYDVR0PBAQDAgEGMBEGCWCGSAGG+EIBAQQE\r\nAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEB\r\nCwUAA4ICAQB31a76byFIgPwjc8ZPClW9wOLq9Y3/QpCVR+aVOqxAXborSJLlA1J3\r\nvSUC8rZIfVOvOqZ/hK7CSTkl1nZJWh7QeaPFm+GukC/q6EovKMWRCzK+kmyin7yz\r\nveH93BQRGkidtfMv03NmbLe3WvUn6UKYhasnqVyR2OIR0TvWbeB+Cyv3NeL8nPSZ\r\nWtAXxu5t7anRCXIJ1OGwKIsvFZ3TAKhJxiX9RiEytm43EJFdfzsAgqg8BZH6usWN\r\nHlif7ZqoY5Zwg2HGoXSPwDgyBxQmwh68YMdDuiTywbWV3UH0uXpvqpl7CVoLf8T0\r\n8PSGSiY6J6rQshduzCe3kwD6Phk8rfr37UlIQGScW06OBY8qn5C0yduWfe4JCpY0\r\nbnozLgQV5He8JBzauFHL3ArFpAQ++0HxGh/yfAykA9jfa6ql7ZMyGxCs4bSHUA+M\r\nLDBLpCV9tbBT3UNm/LCeSftnBym5iqjjlGGPVtoBsZXubHWnXqgwWSbZZk8xPxdv\r\nSAZjRFrYGAz4Q0ogvbZN0KBOD1vlTyc2fk2KM5FfUJQlSpSDLMARk/43dIYLBZM0\r\noQixhID6Fnccur9AWaR4W/knd45cuEG3xiDH/3pUToqLQ0khYxaUNvrfGfDiKmjf\r\nV0vy3Ema4JYq5w/4D825mfkH0BJEN94LdsLho7eexw9LuKyBArU9ww==\r\n-----END CERTIFICATE-----\r\nBag Attributes\r\n    friendlyName: server_op\r\n    localKeyID: 49 94 37 79 51 B9 AA A2 20 59 8C 1B 6F 9A F3 40 31 16 03 8B\r\nKey Attributes: <No Attributes>\r\n"
  }
  jwk {
	  kid = "rsa4"
	  alg = "RS256" 
	  use = "sig" 
	   pem_certificate = "-----BEGIN CERTIFICATE-----\r\nMIIEwTCCAqmgAwIBAgIID+K+XgJff98wDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\r\nBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhB\r\ndXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcwNjE5NTEwMFoXDTIzMDcw\r\nNjE5NTEwMFowUzELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdW\r\naXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTESMBAGA1UEAwwJc2VydmVyX29wMIIB\r\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA71UPBn2cS7qP89sdIlWEv2Kr\r\nsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+r\r\nMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTbo\r\nHYadJ5l/rjpRSNxE7i7b34Bi1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw\r\n/5fF+HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2\r\nJt+DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQID\r\nAQABo4GbMIGYMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGrTFrTNXRXUDJwCxueM\r\nIhznWSw9MAsGA1UdDwQEAwID6DATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREE\r\nDTALgglzZXJ2ZXJfb3AwEQYJYIZIAYb4QgEBBAQDAgZAMB4GCWCGSAGG+EIBDQQR\r\nFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACBKbO/kmaQ2HGxj\r\nmy4Vnap5D45ydgOVzFy1juw/QhyyX+Cth71CONt/39tJlE12vJcqcZxV1JMnY3JI\r\n5rrX62YxuczCrU5W2+Xn5Jo7lY0mFvGbi89bXQruHIDMnLpyXw4Ri5UkaMTuG/cr\r\nAj26pMGnCcWFhos7knKQQ4Yu2zwYymhNWlVAbNxTPvM5fcTHSNB2nxU/Q8UqOIzF\r\nAKL1iCBPlF3BDaLijQxA6aGYzouiefnzy3ODjOuIy3qM4yfD1gh9jHrRs+h+TJZ3\r\nPQ4xZfBkgVMkQcOcsjWEOZf+uXQTVMHF7Y4c41u8VG3IljLCS0ipD86nLq9wbTYR\r\nlA3to3IRCj9PwGCZIUALqmmmgRnw834P90mp8GsLtTbVTGO/zLRI46MHeeLiJmea\r\nHVItOpqn5ahpiauqrdXpoGTlecqmfAkyREn64xkTwGqDqL5X0NMIXre+7ydZb56P\r\npZFb8CBviEGmTW6hYvsqHp7E3phPoOs72zww1jTipCC43DrGbYk/FoBjj6SORHpE\r\n456Zaj7rboJortVwkI8uwzg799wimTWvz2kGQT4+zDvQMa38XrEuAO8fhqf+2I9Q\r\nSSLrHMO4MyflFnuLf8KLC3ochRzCJDbkB9K8s/DiELK3pj7NZXwUzT5pxF3n5oZD\r\nm/0k4YruLQ7bFY+/xjRBH+741916\r\n-----END CERTIFICATE-----"
  }
  jwk {
	  kid = "rsa5"
	  alg = "RS256" 
	  use = "sig" 
	   pem_certificate = "Bag Attributes\r\n    friendlyName: server_op\r\n    localKeyID: 49 94 37 79 51 B9 AA A2 20 59 8C 1B 6F 9A F3 40 31 16 03 8B\r\nsubject=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=server_op\r\nissuer=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=rsa_ca\r\n-----BEGIN CERTIFICATE-----\r\nMIIEwTCCAqmgAwIBAgIID+K+XgJff98wDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\r\nBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhB\r\ndXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcwNjE5NTEwMFoXDTIzMDcw\r\nNjE5NTEwMFowUzELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdW\r\naXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTESMBAGA1UEAwwJc2VydmVyX29wMIIB\r\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA71UPBn2cS7qP89sdIlWEv2Kr\r\nsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+r\r\nMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTbo\r\nHYadJ5l/rjpRSNxE7i7b34Bi1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw\r\n/5fF+HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2\r\nJt+DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQID\r\nAQABo4GbMIGYMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGrTFrTNXRXUDJwCxueM\r\nIhznWSw9MAsGA1UdDwQEAwID6DATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREE\r\nDTALgglzZXJ2ZXJfb3AwEQYJYIZIAYb4QgEBBAQDAgZAMB4GCWCGSAGG+EIBDQQR\r\nFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACBKbO/kmaQ2HGxj\r\nmy4Vnap5D45ydgOVzFy1juw/QhyyX+Cth71CONt/39tJlE12vJcqcZxV1JMnY3JI\r\n5rrX62YxuczCrU5W2+Xn5Jo7lY0mFvGbi89bXQruHIDMnLpyXw4Ri5UkaMTuG/cr\r\nAj26pMGnCcWFhos7knKQQ4Yu2zwYymhNWlVAbNxTPvM5fcTHSNB2nxU/Q8UqOIzF\r\nAKL1iCBPlF3BDaLijQxA6aGYzouiefnzy3ODjOuIy3qM4yfD1gh9jHrRs+h+TJZ3\r\nPQ4xZfBkgVMkQcOcsjWEOZf+uXQTVMHF7Y4c41u8VG3IljLCS0ipD86nLq9wbTYR\r\nlA3to3IRCj9PwGCZIUALqmmmgRnw834P90mp8GsLtTbVTGO/zLRI46MHeeLiJmea\r\nHVItOpqn5ahpiauqrdXpoGTlecqmfAkyREn64xkTwGqDqL5X0NMIXre+7ydZb56P\r\npZFb8CBviEGmTW6hYvsqHp7E3phPoOs72zww1jTipCC43DrGbYk/FoBjj6SORHpE\r\n456Zaj7rboJortVwkI8uwzg799wimTWvz2kGQT4+zDvQMa38XrEuAO8fhqf+2I9Q\r\nSSLrHMO4MyflFnuLf8KLC3ochRzCJDbkB9K8s/DiELK3pj7NZXwUzT5pxF3n5oZD\r\nm/0k4YruLQ7bFY+/xjRBH+741916\r\n-----END CERTIFICATE-----\r\nBag Attributes: <No Attributes>\r\nsubject=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=rsa_ca\r\nissuer=/C=br/ST=ES/L=Vitoria/O=Authlete/CN=rsa_ca\r\n-----BEGIN CERTIFICATE-----\r\n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\r\n-----END CERTIFICATE-----\r\nBag Attributes\r\n    friendlyName: server_op\r\n    localKeyID: 49 94 37 79 51 B9 AA A2 20 59 8C 1B 6F 9A F3 40 31 16 03 8B\r\nKey Attributes: <No Attributes>\r\n"
  }
}
`

// ++++++++++++++++++++++++++++
// client tests constants

const stateSimpleClientState = `
provider "authlete" {
}


resource "authlete_client" "client1" {
	developer = "test"
	client_id_alias = "terraform_client"
    client_id_alias_enabled = false
	client_type = "CONFIDENTIAL"
	redirect_uris = [ "https://www.authlete.com/cb" ]
    response_types = [ "CODE" ]
	grant_types = [ "AUTHORIZATION_CODE", "REFRESH_TOKEN" ]
	client_name = "Authlete client"
    requestable_scopes = ["openid", "profile"]
}

`

const stateDynamicServiceState = `
provider "authlete" {
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Service for client test"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  supported_scopes {
	name = "scope1"
    default_entry = false
  }
  supported_scopes {
	name = "scope2"
    default_entry = false
  }
}

resource "authlete_client" "client1" {
	service_api_key = authlete_service.prod.id
	service_api_secret = authlete_service.prod.api_secret
	developer = "test"
	client_id_alias = "terraform_client"
    client_id_alias_enabled = false
	client_type = "CONFIDENTIAL"
	redirect_uris = [ "https://www.authlete.com/cb" ]
    response_types = [ "CODE" ]
	grant_types = [ "AUTHORIZATION_CODE", "REFRESH_TOKEN" ]
	client_name = "Authlete client"
    requestable_scopes = ["scope1", "scope2"]
}

`

const clientRsaCert = "-----BEGIN CERTIFICATE-----\nMIIEqTCCApGgAwIBAgIIMS7U5PYTrDcwDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\nBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhB\ndXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcxMTE0MjgwMFoXDTIzMDcx\nMTE0MjgwMFowUTELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAmVzMRAwDgYDVQQHEwd2\naXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTEQMA4GA1UEAwwHcnNhX2NsaTCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+Mn+vwYxJ6OsiHymHm9WprWamo\noT3x/qEtx41JQBWYFiEIHJS8fAYQIwqzNlzrn2WJJuH1kdG89hSDi6slSxYCt3ZH\nwpiNtaD8VqPH1GF0EL31n1IFXKjFECjKUhcvu07ow9WzoJ1ti+G8U/d1edjJOsTg\ndhrc+ehdhJA0PWUigLfCq639jHkFTAR37B3KXoNqVUROY39gMbx5V/PKCpwh7HoL\nlyydUnebb0qLtTwWIJgpGCV2vGuNj9CEJpN9NA3xX8pvG3YIZJjuuPCSZWIyps+t\n2BM+s799emygVu+PUIVG97/2Fh5dhTJ8dJo8eokYIH83tmwNmFCrezFkT4UCAwEA\nAaOBhTCBgjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRq3YyxPGBl1t94kjg7oBvv\n+uSCHzALBgNVHQ8EBAMCA7gwEwYDVR0lBAwwCgYIKwYBBQUHAwIwEQYJYIZIAYb4\nQgEBBAQDAgWgMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZI\nhvcNAQELBQADggIBAIt85Da0F8WvMXiFlaGMew+2vzoXzyZ5GYEvniHPjRIgO9f1\nurgXEjMKxS1dfn87Zd2TrTTO/UwbkTh6WnMgs5Uuhg9EYeZJ1tbHW3jdrbWOUFzD\napImM/JElO4k+Srdcr97m9lN9k8AWPK8IJWGrvvMnwkAQ4rT3gUIUe027CwFw2rL\n1UsUqpg2ZglzifLm6HcGJoC76eJi86+k+9+9rT02pWPvcvfIq+P3S6ZUjODoIF8O\nvuLG7SJXlssBMWY5rb/IyGhTvj/1lY0p0A41VbkC4jZLp1Ar69ukorh5Wnzaqtv3\nHsQ0o+07cxxVCgHdyBXZ5x/1SVPaKvBze2Klwzm+UXwT3miu1HiS26cX6Aa2WymF\nwtsK1m0NRIUx1H84eT77QvTeDx3IHlQFtOptoC7Mu8UQid7fbCzbk72+eHB5QE2I\nDAsT3+D/Th76w4fKh2v29/Si+tjT9/MqoQkERxTF/OMvhpriveoJ3p0Oilg15zCo\nmFstj6WplC1hjLmLOlaKwsi9BhmqBKTp84hD0GKiDExIezak8Z3yM5cdVi5d+mT+\ncO495Ispzt9Wgm5WHNldsIG0zsrPFYPC+8YRAw4aDMVqDj6RpB0quijhchyPp6Zc\nTENi9zQx9Bz8oIZwSTQOly8xxz04an4K/8pMGaVfBsSW7EQoueiR+69mucah\n-----END CERTIFICATE-----\n"

const pemSupportClientTests = `
provider "authlete" {
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Service for client test"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  supported_scopes {
	name = "scope1"
    default_entry = false
  }
  supported_scopes {
	name = "scope2"
    default_entry = false
  }
}

resource "authlete_client" "client1" {
	service_api_key = authlete_service.prod.id
	service_api_secret = authlete_service.prod.api_secret
	developer = "test"
	client_id_alias = "terraform_client"
    client_id_alias_enabled = false
	client_type = "CONFIDENTIAL"
	redirect_uris = [ "https://www.authlete.com/cb" ]
    response_types = [ "CODE" ]
	grant_types = [ "AUTHORIZATION_CODE", "REFRESH_TOKEN" ]
	client_name = "Authlete client"
    requestable_scopes = ["scope1", "scope2"]

    jwk {
	  kid = "rsa1"
	  alg = "RS256" 
	  use = "sig" 
	  pem_certificate = "-----BEGIN CERTIFICATE-----\nMIIEqTCCApGgAwIBAgIIMS7U5PYTrDcwDQYJKoZIhvcNAQELBQAwUDELMAkGA1UE\nBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhB\ndXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcxMTE0MjgwMFoXDTIzMDcx\nMTE0MjgwMFowUTELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAmVzMRAwDgYDVQQHEwd2\naXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTEQMA4GA1UEAwwHcnNhX2NsaTCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+Mn+vwYxJ6OsiHymHm9WprWamo\noT3x/qEtx41JQBWYFiEIHJS8fAYQIwqzNlzrn2WJJuH1kdG89hSDi6slSxYCt3ZH\nwpiNtaD8VqPH1GF0EL31n1IFXKjFECjKUhcvu07ow9WzoJ1ti+G8U/d1edjJOsTg\ndhrc+ehdhJA0PWUigLfCq639jHkFTAR37B3KXoNqVUROY39gMbx5V/PKCpwh7HoL\nlyydUnebb0qLtTwWIJgpGCV2vGuNj9CEJpN9NA3xX8pvG3YIZJjuuPCSZWIyps+t\n2BM+s799emygVu+PUIVG97/2Fh5dhTJ8dJo8eokYIH83tmwNmFCrezFkT4UCAwEA\nAaOBhTCBgjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRq3YyxPGBl1t94kjg7oBvv\n+uSCHzALBgNVHQ8EBAMCA7gwEwYDVR0lBAwwCgYIKwYBBQUHAwIwEQYJYIZIAYb4\nQgEBBAQDAgWgMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZI\nhvcNAQELBQADggIBAIt85Da0F8WvMXiFlaGMew+2vzoXzyZ5GYEvniHPjRIgO9f1\nurgXEjMKxS1dfn87Zd2TrTTO/UwbkTh6WnMgs5Uuhg9EYeZJ1tbHW3jdrbWOUFzD\napImM/JElO4k+Srdcr97m9lN9k8AWPK8IJWGrvvMnwkAQ4rT3gUIUe027CwFw2rL\n1UsUqpg2ZglzifLm6HcGJoC76eJi86+k+9+9rT02pWPvcvfIq+P3S6ZUjODoIF8O\nvuLG7SJXlssBMWY5rb/IyGhTvj/1lY0p0A41VbkC4jZLp1Ar69ukorh5Wnzaqtv3\nHsQ0o+07cxxVCgHdyBXZ5x/1SVPaKvBze2Klwzm+UXwT3miu1HiS26cX6Aa2WymF\nwtsK1m0NRIUx1H84eT77QvTeDx3IHlQFtOptoC7Mu8UQid7fbCzbk72+eHB5QE2I\nDAsT3+D/Th76w4fKh2v29/Si+tjT9/MqoQkERxTF/OMvhpriveoJ3p0Oilg15zCo\nmFstj6WplC1hjLmLOlaKwsi9BhmqBKTp84hD0GKiDExIezak8Z3yM5cdVi5d+mT+\ncO495Ispzt9Wgm5WHNldsIG0zsrPFYPC+8YRAw4aDMVqDj6RpB0quijhchyPp6Zc\nTENi9zQx9Bz8oIZwSTQOly8xxz04an4K/8pMGaVfBsSW7EQoueiR+69mucah\n-----END CERTIFICATE-----\n"
    }
}


`
