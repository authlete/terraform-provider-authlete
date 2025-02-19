package provider

import (
	"context"
	"crypto/tls"
	"fmt"

	"net/http"
	"os"
	"strconv"
	"testing"

	idp "github.com/authlete/idp-api"
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

	if soKey == "" || soSecret == "" {
		t.Fatal("Environment variables AUTHLETE_SO_KEY and AUTHLETE_SO_SECRET are required for acceptance test")
	}

}

func testCreateTestService(t *testing.T, service2 IService) {
	var err error = nil
	var newService IService
	var apiServerId, organizationId int
	var orgToken string

	authleteClient, auth := createTestClient()
	apiServerId, err = strconv.Atoi(os.Getenv("AUTHLETE_API_SERVER_ID"))
	if err != nil {
		t.Fatal("Error during converting AUTHLETE_API_SERVER_ID to integer ", err)
	}
	organizationId, err = strconv.Atoi(os.Getenv("AUTHLETE_ORGANIZATION_ID"))
	if err != nil {
		t.Fatal("Error during converting AUTHLETE_ORGANIZATION_ID to integer ", err)
	}
	createSvcReq := idp.NewCreateServiceRequest(int64(apiServerId), int64(organizationId))
	createSvcReq.SetService(*service2.(*idp.Service))
	orgToken = convertToBearerToken(auth.Value(authlete3.ContextAccessToken).(string))
	newService, _, err = authleteClient.(*idp.ServiceApiAPIService).CreateService(context.Background()).
		CreateServiceRequest(*createSvcReq).Authorization(orgToken).Execute()

	if err != nil {
		t.Fatal("Error while setup the test ", err)
	}
	service2.SetApiKey(newService.GetApiKey())

	service2.SetApiSecret(os.Getenv("AUTHLETE_SO_SECRET"))

	_ = os.Setenv("AUTHLETE_API_KEY", strconv.FormatInt(service2.GetApiKey(), 10))
	_ = os.Setenv("AUTHLETE_API_SECRET", service2.GetApiSecret())

	testAccProvider = New("dev")()

}

func createTestClient() (ServiceManagementApi, context.Context) {

	soSecret := os.Getenv("AUTHLETE_SO_SECRET")
	apiServer := os.Getenv("AUTHLETE_API_SERVER")
	idpServer := os.Getenv("AUTHLETE_IDP_SERVER")

	if apiServer == "" {
		apiServer = "https://api.authlete.com"
	}

	auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, soSecret)
	cnf := idp.NewConfiguration()
	tlsInsecure := os.Getenv("AUTHLETE_TLS_INSECURE")
	if tlsInsecure == "true" {
		mTLSConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		tr := &http.Transport{
			TLSClientConfig: mTLSConfig,
		}
		cnf.HTTPClient = &http.Client{Transport: tr}
	}
	cnf.UserAgent = "terraform-provider-authlete"
	cnf.Servers[0].URL = idpServer
	apiClientOpenAPI := idp.NewAPIClient(cnf)
	return apiClientOpenAPI.ServiceApiAPI, auth

}

func testDestroyTestService(t *testing.T, service2 IService) {
	var err error = nil
	var apiServerId, organizationId int
	var serviceId int64
	var orgToken string
	authleteClient, auth := createTestClient()

	apiServerId, err = strconv.Atoi(os.Getenv("AUTHLETE_API_SERVER_ID"))
	if err != nil {
		t.Fatal("Error during converting AUTHLETE_API_SERVER_ID to integer ", err)
	}
	organizationId, err = strconv.Atoi(os.Getenv("AUTHLETE_ORGANIZATION_ID"))
	if err != nil {
		t.Fatal("Error during converting AUTHLETE_ORGANIZATION_ID to integer ", err)
	}
	serviceId = service2.GetApiKey()
	if serviceId == 0 {
		t.Fatal("Error getting service api_key")
	}
	deleteSvcReq := idp.NewDeleteServiceRequest(int64(apiServerId), int64(organizationId), serviceId)
	orgToken = "Bearer " + auth.Value(authlete3.ContextAccessToken).(string)
	_, err = authleteClient.(*idp.ServiceApiAPIService).DeleteService(context.Background()).Authorization(orgToken).
		DeleteServiceRequest(*deleteSvcReq).Execute()

	if err != nil {
		t.Fatal("Error during teardown the test ", err)
	}

}

func pullServiceFromServer(s *terraform.State) (authlete3.Service, error) {

	client := testAccProvider.Meta().(*apiClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "authlete_service" {
			continue
		}

		auth := context.WithValue(context.Background(), authlete3.ContextAccessToken, client.serviceOwnerSecret)
		response, _, err := client.authleteClient.v3.ServiceManagementAPI.ServiceGetApi(auth, rs.Primary.ID).Execute()

		if err != nil {
			return authlete3.Service{}, fmt.Errorf("Service (%s) could not be found.", rs.Primary.ID)
		}

		return *response.Service, nil
	}
	return authlete3.Service{}, fmt.Errorf(
		"authlete service not found")
}

func testServiceDestroy(s *terraform.State) error {

	response, err := pullServiceFromServer(s)

	if err == nil && response.GetApiKey() != 0 {
		return fmt.Errorf("Service still exists.")
	}
	return nil
}
