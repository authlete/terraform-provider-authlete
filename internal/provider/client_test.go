package provider

import (
	"testing"

	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestClient_create_import(t *testing.T) {
	openid := "openid"
	profile := "profile"
	var testService *authlete.Service
	testService = authlete.NewService()
	testService.SetServiceName("Test Service for client testing")
	testService.SetIssuer("https://test.com")
	testService.SetSupportedGrantTypes([]authlete.GrantType{
		authlete.GRANTTYPE_AUTHORIZATION_CODE,
		authlete.GRANTTYPE_REFRESH_TOKEN})
	testService.SetSupportedResponseTypes(
		[]authlete.ResponseType{authlete.RESPONSETYPE_CODE})
	testService.SupportedScopes = []authlete.Scope{
		{
			Name: &openid,
		},
		{
			Name: &profile,
		},
	}
	//testService.SetJwks("")
	defer testDestroyTestService(t, testService)
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testCreateTestService(t, testService)
		},
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: stateSimpleClientState,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_id"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),
				),
			},
			{
				ResourceName:            "authlete_client.client1",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"client_id", "client_secret"},
			},
		},
	})

}

func TestClient_dynamic_services(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: stateDynamicServiceState,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_id"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),
				),
			},
		},
	})
}

func TestClient_pem_cert_support(t *testing.T) {

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: pemSupportClientTests,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authlete_client.client1", "client_id_alias", "terraform_client"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_id"),
					resource.TestCheckResourceAttrSet("authlete_client.client1", "client_secret"),
					resource.TestCheckResourceAttr("authlete_client.client1", "jwk.#", "1"),
				),
			},
		},
	})
}
