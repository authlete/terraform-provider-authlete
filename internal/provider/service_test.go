package provider

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceService(t *testing.T) {

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceServiceDefaultValues,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.prod", "issuer", "https://test.com"),
					resource.TestCheckFunc(CheckOutputPresent("api_key")),
					resource.TestCheckFunc(CheckOutputPresent("api_secret")),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_grant_types.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_grant_types.0", "AUTHORIZATION_CODE"),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_grant_types.1", "REFRESH_TOKEN"),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_response_types.#", "1"),
					resource.TestCheckResourceAttr("authlete_service.prod", "supported_response_types.0", "CODE"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_authorization_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_token_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_revocation_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_user_info_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "direct_introspection_endpoint_enabled", "false"),
					resource.TestCheckResourceAttr("authlete_service.prod", "single_access_token_per_subject", "true"),
				),
			},
			{
				Config: testAccResourceServiceEveryAttribute,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.prod", "issuer", "https://test.com"),
				),
			}
			{
				Config: testAccGenerateRSAKeys,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.prod", "jwk.#", "9"),
				),
			},
			{
				Config: testAccGenerateECKeys,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.prod", "jwk.#", "6"),
				),
			},
		},
	})
}

func testServiceDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*apiClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "authlete_service" {
			continue
		}

		response, err := client.authleteClient.GetService(rs.Primary.ID)
		if err == nil {
			if response != nil {
				return fmt.Errorf("Service (%s) still exists.", rs.Primary.ID)
			}
			return nil
		}
	}

	return nil
}

const testAccResourceServiceDefaultValues = `

provider "authlete" {
	
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Simples Test API"
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

const testAccGenerateRSAKeys = `


provider "authlete" {
	
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "RS256"
  access_token_signature_key_id = "rsa1"
  jwk {
	  kid = "rsa1"
	  alg = "RS256" 
	  use = "sig" 
	  kty = "RSA"
      generate = true
   }
   jwk {
	  kid = "rsa2"
	  alg = "RS384" 
	  use = "sig" 
	  kty = "RSA"
      generate = true
   }
   jwk {
	  kid = "rsa3"
	  alg = "RS512" 
	  use = "sig" 
	  kty = "RSA"
      generate = true
   }
   jwk {
	kid = "psa1"
	alg = "PS256" 
	use = "sig"
    generate = true
   } 
   jwk {
	kid = "psa2"
	alg = "PS384" 
	use = "sig"
    generate = true
   } 
   jwk {
	kid = "psa3"
	alg = "PS512" 
	use = "sig"
    generate = true
   } 
   jwk {
	kid = "encrsa1"
	alg = "RSA-OAEP" 
	use = "enc"
    generate = true
   } 
   jwk {
	kid = "encrsa2"
	alg = "RSA-OAEP-256" 
	use = "enc" 
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

const testAccGenerateECKeys = `


provider "authlete" {
	
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Test API"
  supported_grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  supported_response_types = ["CODE"]
  access_token_sign_alg = "ES256"
  access_token_signature_key_id = "ec1"
  jwk {
	  kid = "ec1"
	  alg = "ES256" 
	  use = "sig"
      generate = true
   }
  jwk {
	  kid = "ec3"
	  alg = "ES384" 
	  use = "sig"
      generate = true
   }
  jwk {
	  kid = "ec4"
	  alg = "ES512" 
	  use = "sig"
      generate = true
   }
   jwk {
	  kid = "enc1"
	  alg = "ECDH-ES" 
	  use = "enc"
      generate = true
   }
   jwk {
	  kid = "enc2"
	  alg = "ECDH-ES+A128KW" 
	  use = "enc"
      generate = true
   }
   jwk {
	kid = "enc3"
	alg = "ECDH-ES+A192KW" 
	use = "enc"
    generate = true
   }
}
`

const testAccResourceServiceEveryAttribute = `

provider "authlete" {
	
}

resource "authlete_service" "prod" {
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
  supported_acr = ["loa2", "loa3"]
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
}

output "api_key" {  
  value = authlete_service.prod.id
}
output "api_secret" {  
  value = authlete_service.prod.api_secret
}
`

func CheckOutputPresent(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ms := s.RootModule()
		rs, ok := ms.Outputs[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		if rs.Value == nil {
			return fmt.Errorf(
				"Output '%s': expected to have a value, got %#v",
				name,
				rs)
		}

		return nil
	}
}
