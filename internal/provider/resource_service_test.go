package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceService(t *testing.T) {
	//t.Skip("resource not yet implemented, remove this once you add your own code")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			/*{
				Config: testAccResourceService,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.prod", "issuer", "https://test.com"),
				),
			},*/
			{
				Config: testAccResourceServiceJWKS,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.prod", "issuer", "https://test.com"),
				),
			},
		},
	})
}

const testAccResourceService = `

provider "authlete" {
	
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Test API"
  supported_revocation_auth_methods = ["NONE"]
}
`

const testAccResourceServiceJWKS = `


provider "authlete" {
	
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Test API"
  clients_per_developer = 10
  supported_revocation_auth_methods = ["NONE"]
  access_token_sign_alg = "RS256"
  access_token_signature_key_id = "kid1"
  jwk {
	  kid = "kid1"
	  alg = "RS256" 
	  use = "sig" 
	  kty = "OCR"
   } 
   jwk {
	kid = "kid2"
	alg = "PS256" 
	use = "sig" 
	kty = "OCR"
   } 
   jwk {
	kid = "kid3"
	alg = "RS256" 
	use = "sig" 
	generate = true
  
   }
   supported_scopes {
	   name = "payment"
	
	   description = "scope that grants the permission to 3rd party to start payment"

	   attribute {
		   key = "key1"
		   value = "val1"
	   }

	   attribute {
		key = "fapi"
		value = "rw"
	   }
    }

	supported_scopes {
		name = "openid"
	 
 
	 }
}
`
