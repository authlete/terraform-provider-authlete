package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/authlete/authlete-go-openapi"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider

func init() {
	testAccProvider = New("dev")()
	testAccProviders = map[string]*schema.Provider{"authlete": testAccProvider}
}

// providerFactories are used to instantiate a provider during acceptance testing.
// The factory function will be invoked for every Terraform CLI command executed
// to create a provider server to which the CLI can reattach.
var providerFactories = map[string]func() (*schema.Provider, error){
	"authlete": func() (*schema.Provider, error) {
		return testAccProvider, nil
	},
}

func TestProvider(t *testing.T) {
	if err := New("dev")().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func testAccPreCheck(t *testing.T) {

	so_key := os.Getenv("AUTHLETE_SO_KEY")
	so_secret := os.Getenv("AUTHLETE_SO_SECRET")

	if so_key == "" || so_secret == "" {
		t.Fatal("Environment variables AUTHLETE_SO_KEY and AUTHLETE_SO_SECRET are required for acceptance test")
	}

}

func testCreateTestService(t *testing.T, service2 *authlete.Service) {

	authleteClient, auth := createTestClient()

	newService, _, err := authleteClient.ServiceCreateApi(auth).Service(*service2).Execute()

	if err != nil {
		t.Fatal("Error while setup the test ", err)
	}
	service2.ApiKey = newService.ApiKey
	service2.ApiSecret = newService.ApiSecret

	os.Setenv("AUTHLETE_API_KEY", strconv.FormatInt(service2.GetApiKey(), 10))
	os.Setenv("AUTHLETE_API_SECRET", service2.GetApiSecret())

	testAccProvider = New("dev")()
	testAccProviders = map[string]*schema.Provider{"authlete": testAccProvider}

}

func createTestClient() (authlete.ServiceManagementApi, context.Context) {
	so_key := os.Getenv("AUTHLETE_SO_KEY")
	so_secret := os.Getenv("AUTHLETE_SO_SECRET")
	api_server := os.Getenv("AUTHLETE_API_SERVER")

	if api_server == "" {
		api_server = "https://api.authlete.com/api"
	}

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: so_key,
		Password: so_secret,
	})

	cnf := authlete.NewConfiguration()
	cnf.UserAgent = "terraform-provider-authlete"

	cnf.Servers[0].URL = api_server

	apiClientOpenAPI := authlete.NewAPIClient(cnf)

	return apiClientOpenAPI.ServiceManagementApi, auth
}

func testDestroyTestService(t *testing.T, service2 *authlete.Service) {
	authleteClient, auth := createTestClient()

	_, err := authleteClient.ServiceDeleteApi(auth, strconv.FormatInt(service2.GetApiKey(), 10)).Execute()

	if err != nil {
		t.Fatal("Error during teardown the test ", err)
	}

}

func pullServiceFromServer(s *terraform.State) (*authlete.Service, error) {
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
			return response, fmt.Errorf("Service (%s) could not be found.", rs.Primary.ID)
		}

		return response, nil
	}
	return &authlete.Service{}, fmt.Errorf(
		"authlete service not found")
}

func testServiceDestroy(s *terraform.State) error {

	response, err := pullServiceFromServer(s)

	if err == nil && response != nil {
		return fmt.Errorf("Service still exists.")
	}

	return nil
}
