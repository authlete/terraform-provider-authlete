package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

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
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.kid", "rsa1"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.alg", "RS256"),
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

func TestAccResourceServiceCrypto_import(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGenerateRSAKeys_import,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.import", "jwk.#", "2"),
					resource.TestCheckResourceAttr("authlete_service.import", "jwk.0.kid", "rsa1"),
					resource.TestCheckResourceAttr("authlete_service.import", "jwk.0.alg", "PS256"),
				),
			},
			{
				ResourceName:            "authlete_service.import",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"api_secret"},
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

func findJWKStructure(s *terraform.State, kid string) (JWKStruct, error) {
	client := testAccProvider.Meta().(*apiClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "authlete_service" {
			continue
		}

		auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
			UserName: client.service_owner_key,
			Password: client.service_owner_secret,
		})

		response, _, err := client.authleteClient.ServiceManagementApi.ServiceGetApi(auth, rs.Primary.ID).Execute()
		if err != nil {
			return JWKStruct{}, err
		}

		var keysMap map[string][]JWKStruct
		json.Unmarshal([]byte(*response.Jwks), &keysMap)

		var keys = keysMap["keys"]

		for _, jwkStruct := range keys {
			if jwkStruct.Kid == kid {
				return jwkStruct, nil
			}
		}
	}

	return JWKStruct{}, fmt.Errorf("Key %s not found on Service", kid)
}

const testAccGenerateRSAKeys_import = `
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
