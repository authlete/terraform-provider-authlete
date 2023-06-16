package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	authlete "github.com/authlete/openapi-for-go"
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type ServiceManagementApi interface{}

var testAccProvider *schema.Provider

func init() {
	testAccProvider = New("dev")()
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

	soKey := os.Getenv("AUTHLETE_SO_KEY")
	soSecret := os.Getenv("AUTHLETE_SO_SECRET")
	authVersion := os.Getenv("TC_ACC_AUTHLETE_VERSION")

	if soKey == "" || soSecret == "" {
		t.Fatal("Environment variables AUTHLETE_SO_KEY and AUTHLETE_SO_SECRET are required for acceptance test")
	}

	if authVersion == "3.0" {
		v3 = true
	}
}

func testCreateTestService(t *testing.T, service2 IService) {
	var err error = nil
	var newService IService

	authleteClient, auth := createTestClient()
	if v3 {
		s, _ := service2.(*authlete3.Service)
		newService, _, err = authleteClient.(authlete3.ServiceManagementApi).ServiceCreateApi(auth).Service(*s).Execute()
	} else {
		s, _ := service2.(*authlete.Service)
		newService, _, err = authleteClient.(authlete.ServiceManagementApi).ServiceCreateApi(auth).Service(*s).Execute()
	}

	if err != nil {
		t.Fatal("Error while setup the test ", err)
	}
	service2.SetApiKey(newService.GetApiKey())
	if v3 {
		service2.SetApiSecret(os.Getenv("AUTHLETE_SO_SECRET"))
	} else {
		service2.SetApiSecret(newService.GetApiSecret())
	}

	_ = os.Setenv("AUTHLETE_API_KEY", strconv.FormatInt(service2.GetApiKey(), 10))
	_ = os.Setenv("AUTHLETE_API_SECRET", service2.GetApiSecret())

	testAccProvider = New("dev")()

}

func createTestClient() (ServiceManagementApi, context.Context) {
	soKey := os.Getenv("AUTHLETE_SO_KEY")
	soSecret := os.Getenv("AUTHLETE_SO_SECRET")
	apiServer := os.Getenv("AUTHLETE_API_SERVER")

	if apiServer == "" {
		apiServer = "https://api.authlete.com"
	}

	if v3 {
		auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, soSecret)
		cnf := authlete3.NewConfiguration()
		cnf.UserAgent = "terraform-provider-authlete"
		cnf.Servers[0].URL = apiServer
		apiClientOpenAPI := authlete3.NewAPIClient(cnf)
		return apiClientOpenAPI.ServiceManagementApi, auth
	}

	auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
		UserName: soKey,
		Password: soSecret,
	})

	cnf := authlete.NewConfiguration()
	cnf.UserAgent = "terraform-provider-authlete"

	cnf.Servers[0].URL = apiServer

	apiClientOpenAPI := authlete.NewAPIClient(cnf)

	return apiClientOpenAPI.ServiceManagementApi, auth
}

func testDestroyTestService(t *testing.T, service2 IService) {
	var err error = nil
	authleteClient, auth := createTestClient()

	t.Log("service api_key", service2.GetApiKey())
	if v3 {
		_, err = authleteClient.(authlete3.ServiceManagementApi).ServiceDeleteApi(auth, strconv.FormatInt(service2.GetApiKey(), 10)).Execute()
	} else {
		_, err = authleteClient.(authlete.ServiceManagementApi).ServiceDeleteApi(auth, strconv.FormatInt(service2.GetApiKey(), 10)).Execute()
	}

	if err != nil {
		t.Fatal("Error during teardown the test ", err)
	}

}

func pullServiceFromServer(s *terraform.State) (IService, error) {
	var err error = nil
	var response IService
	client := testAccProvider.Meta().(*apiClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "authlete_service" {
			continue
		}

		if v3 {
			auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, client.serviceOwnerSecret)
			response, _, err = client.authleteClient.v3.ServiceManagementApi.ServiceGetApi(auth, rs.Primary.ID).Execute()
		} else {
			auth := context.WithValue(context.Background(), authlete.ContextBasicAuth, authlete.BasicAuth{
				UserName: client.serviceOwnerKey,
				Password: client.serviceOwnerSecret,
			})
			response, _, err = client.authleteClient.v2.ServiceManagementApi.ServiceGetApi(auth, rs.Primary.ID).Execute()
		}

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
