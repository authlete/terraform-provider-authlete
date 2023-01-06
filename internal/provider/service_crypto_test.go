package provider

import (
	"context"
	"encoding/json"
	"fmt"
	authlete "github.com/authlete/openapi-for-go"
	"testing"

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
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.rsa", "jwk.*",
						map[string]string{
							"kid": "rsa1",
							"alg": "RS256",
						}),
				),
			},
			{
				Config: testAccGenerateRSAKeys,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.#", "9"),
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.rsa", "jwk.*",
						map[string]string{
							"kid": "rsa1",
							"alg": "RS256",
						}),
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
				Config: testAccGenerateRSAKeysCreate,
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
				Config: testAccGenerateRSAKeysUpdate,
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
				Config: testAccGenerateRSAKeysImport,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_service.import", "jwk.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs("authlete_service.import", "jwk.*",
						map[string]string{
							"kid": "rsa1",
							"alg": "PS256",
						}),
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
				Config: testAccGenerateECKeysCreate,
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
				Config: testAccGenerateECKeysUpdate,
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

func TestAccPEM_rsa(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPemRSASupport,
				Check: resource.ComposeTestCheckFunc(

					//the 1st is a private key without cert
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.#", "5"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.kid", "rsa1"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.use", "sig"),

					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.kty", ""),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.d", ""),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.dp", ""),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.dq", ""),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.e", ""),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.n", ""),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.p", ""),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.q", ""),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.0.qi", ""),

					//the 2nd is a x509 cert and a private key
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.1.kid", "rsa2"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.1.alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.1.use", "sig"),

					// the 3rd is a full chain cert and private key
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.2.kid", "rsa3"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.2.alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.2.use", "sig"),

					//the last rsa pem has just the cert chain
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.3.kid", "rsa4"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.3.alg", "RS256"),
					resource.TestCheckResourceAttr("authlete_service.rsa", "jwk.3.use", "sig"),
				),
			},
		},
	})
}

func findJWKStructure(s *terraform.State, kid string) (JWKStruct, error) {
	client := testAccProvider.Meta().(*apiClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "authlete_service" {
			continue
		}

		auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
			UserName: client.serviceOwnerKey,
			Password: client.serviceOwnerSecret,
		})

		response, _, err := client.authleteClient.ServiceManagementApi.ServiceGetApi(auth, rs.Primary.ID).Execute()
		if err != nil {
			return JWKStruct{}, err
		}

		var keysMap map[string][]JWKStruct
		_ = json.Unmarshal([]byte(*response.Jwks), &keysMap)

		var keys = keysMap["keys"]

		for _, jwkStruct := range keys {
			if jwkStruct.Kid == kid {
				return jwkStruct, nil
			}
		}
	}

	return JWKStruct{}, fmt.Errorf("Key %s not found on Service", kid)
}
