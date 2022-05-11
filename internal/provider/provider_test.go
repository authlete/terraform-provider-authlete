package provider

import (
	"fmt"
	"github.com/authlete/authlete-go/api"
	"github.com/authlete/authlete-go/conf"
	"github.com/authlete/authlete-go/dto"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"strconv"
	"testing"

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

func testCreateTestService(t *testing.T, service2 *dto.Service) {

	authleteClient := createTestClient()

	newService, err := authleteClient.CreateService(service2)

	if err != nil {
		t.Fatal("Error while setup the test ", err)
	}
	service2.ApiKey = newService.ApiKey
	service2.ApiSecret = newService.ApiSecret

	os.Setenv("AUTHLETE_API_KEY", strconv.FormatUint(service2.ApiKey, 10))
	os.Setenv("AUTHLETE_API_SECRET", service2.ApiSecret)

	testAccProvider = New("dev")()
	testAccProviders = map[string]*schema.Provider{"authlete": testAccProvider}

}

func createTestClient() api.AuthleteApi {
	so_key := os.Getenv("AUTHLETE_SO_KEY")
	so_secret := os.Getenv("AUTHLETE_SO_SECRET")
	cnf := conf.AuthleteSimpleConfiguration{}
	api_server := os.Getenv("AUTHLETE_API_SERVER")
	if api_server == "" {
		api_server = "https://api.authlete.com"
	}
	cnf.SetBaseUrl(api_server)
	cnf.SetServiceOwnerApiKey(so_key)
	cnf.SetServiceOwnerApiSecret(so_secret)

	authleteClient := api.New(&cnf)
	authleteClient.Settings().UserAgent = "terraform-provider-authlete - dev"
	return authleteClient
}

func testDestroyTestService(t *testing.T, service2 *dto.Service) {
	authleteClient := createTestClient()

	err := authleteClient.DeleteService(service2.ApiKey)

	if err != nil {
		t.Fatal("Error during teardown the test ", err)
	}

}

func pullServiceFromServer(s *terraform.State) (*dto.Service, error) {
	client := testAccProvider.Meta().(*apiClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "authlete_service" {
			continue
		}

		response, err := client.authleteClient.GetService(rs.Primary.ID)
		if err != nil {
			return response, fmt.Errorf("Service (%s) could not be found.", rs.Primary.ID)
		}

		return response, nil
	}
	return &dto.Service{}, fmt.Errorf(
		"authlete service not found")
}

func testServiceDestroy(s *terraform.State) error {

	response, err := pullServiceFromServer(s)

	if err == nil && response != nil {
		return fmt.Errorf("Service still exists.")
	}

	return nil
}
