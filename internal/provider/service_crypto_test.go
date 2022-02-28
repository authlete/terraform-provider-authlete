package provider

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceServiceCrypto_rsa(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGenerateRSAKeys,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.#", "9"),
				),
			},
		},
	})
}

func TestAccResourceServiceCrypto_rsa_key_rotation(t *testing.T) {

	var key2 JWKStruct
	var kid = "rsa2"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGenerateRSAKeys_create,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "access_token_signature_key_id", "rsa1"),
					func(s *terraform.State) error {
						key, err := findJWKStructure(s, kid)
						if err != nil {
							return err
						}
						key2 = key
						return nil
					},
				),
			},
			{
				Config: testAccGenerateRSAKeys_update,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "access_token_signature_key_id", "rsa2"),
					func(s *terraform.State) error {
						key, err := findJWKStructure(s, kid)
						if err != nil {
							return err
						}
						jwkStruct := key
						if key2.D == jwkStruct.D &&
							key2.Dp == jwkStruct.Dp &&
							key2.Dq == jwkStruct.Dq &&
							key2.E == jwkStruct.E &&
							key2.Kty == jwkStruct.Kty &&
							key2.N == jwkStruct.N &&
							key2.P == jwkStruct.P &&
							key2.Q == jwkStruct.Q &&
							key2.Qi == jwkStruct.Qi {
							return nil
						}
						return fmt.Errorf("Key2 was changed - created (%s) and updated (%s).", key2, jwkStruct)
					},
				),
			},
		},
	})
}

func TestAccResourceServiceCrypto_ec(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGenerateECKeys,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.ec", "jwk.#", "6"),
				),
			},
		},
	})
}

func TestAccResourceServiceCrypto_ec_key_rotation(t *testing.T) {

	var ec2 JWKStruct
	var enc2 JWKStruct
	var kid = "ec2"
	var kiden = "enc2"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGenerateECKeys_create,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.ec", "access_token_signature_key_id", "ec1"),
					func(s *terraform.State) error {
						key, err := findJWKStructure(s, kid)
						if err != nil {
							return err
						}
						ec2 = key
						return nil
					},
					func(s *terraform.State) error {
						key, err := findJWKStructure(s, kiden)
						if err != nil {
							return err
						}
						enc2 = key
						return nil
					},
				),
			},
			{
				Config: testAccGenerateECKeys_update,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.ec", "access_token_signature_key_id", "ec2"),
					func(s *terraform.State) error {
						key, err := findJWKStructure(s, kid)
						if err != nil {
							return err
						}
						jwkStruct := key
						if ec2.D == jwkStruct.D &&
							ec2.Crv == jwkStruct.Crv &&
							ec2.X == jwkStruct.X &&
							ec2.Y == jwkStruct.Y {
							return nil
						}
						return fmt.Errorf("Key2 was changed - created (%s) and updated (%s).", ec2, jwkStruct)
					},
					func(s *terraform.State) error {
						key, err := findJWKStructure(s, kiden)
						if err != nil {
							return err
						}
						jwkStruct := key
						if enc2.D == jwkStruct.D &&
							enc2.Crv == jwkStruct.Crv &&
							enc2.X == jwkStruct.X &&
							enc2.Y == jwkStruct.Y {
							return nil
						}
						return fmt.Errorf("Key2 was changed - created (%s) and updated (%s).", enc2, jwkStruct)
					},
				),
			},
		},
	})
}

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

const testAccGenerateRSAKeys_create = `
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
      generate = true
   }
   jwk {
	  kid = "rsa2"
	  alg = "RS384" 
	  use = "sig" 
	  kty = "RSA"
      generate = true
   }
}
`
const testAccGenerateRSAKeys_update = `
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
      generate = true
   }
   jwk {
	  kid = "rsa3"
	  alg = "RS384" 
	  use = "sig" 
	  kty = "RSA"
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

const testAccGenerateECKeys_create = `

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
      generate = true
   }
   jwk {
	  kid = "ec2"
	  alg = "ES256" 
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
}
`

const testAccGenerateECKeys_update = `

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
      generate = true
   }
   jwk {
	  kid = "ec3"
	  alg = "ES256" 
	  use = "sig"
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
	  alg = "ECDH-ES" 
	  use = "enc"
      generate = true
   }
   
}
`

func findJWKStructure(s *terraform.State, kid string) (JWKStruct, error) {
	client := testAccProvider.Meta().(*apiClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "authlete_service" {
			continue
		}

		response, err := client.authleteClient.GetService(rs.Primary.ID)
		if err != nil {
			return JWKStruct{}, err
		}

		var keysMap map[string][]JWKStruct
		json.Unmarshal([]byte(response.Jwks), &keysMap)

		var keys = keysMap["keys"]

		for _, jwkStruct := range keys {
			if jwkStruct.Kid == kid {
				return jwkStruct, nil
			}
		}
	}

	return JWKStruct{}, fmt.Errorf("Key %s not found on Service", kid)
}
