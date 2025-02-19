package provider

import (
	"context"
	"crypto/tls"
	authlete "github.com/authlete/openapi-for-go"
	"net/http"
	"os"
	"reflect"

	idp "github.com/authlete/idp-api"
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func init() {
	// Set descriptions to support markdown syntax, this will be used in document generation
	// and the language server.
	schema.DescriptionKind = schema.StringMarkdown

	// Customize the content of descriptions when output. For example you can add defaults on
	// to the exported descriptions if present.
	// schema.SchemaDescriptionBuilder = func(s *schema.Schema) string {
	// 	desc := s.Description
	// 	if s.Default != nil {
	// 		desc += fmt.Sprintf(" Defaults to `%v`.", s.Default)
	// 	}
	// 	return strings.TrimSpace(desc)
	// }
}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"api_server": {
					Type:        schema.TypeString,
					Required:    false,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_API_SERVER", "https://api.authlete.com"),
				},
				"idp_server": {
					Type:        schema.TypeString,
					Required:    false,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_IDP_SERVER", "https://devidp.authlete.net"),
				},
				"api_server_id": {
					Type:        schema.TypeString,
					Required:    false,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_API_SERVER_ID", ""),
				},
				"organization_id": {
					Type:        schema.TypeString,
					Required:    false,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_ORGANIZATION_ID", ""),
				},
				"service_owner_key": {
					Type:        schema.TypeString,
					Required:    true,
					Optional:    false,
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_SO_KEY", ""),
				},
				"service_owner_secret": {
					Type:        schema.TypeString,
					Required:    true,
					Optional:    false,
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_SO_SECRET", ""),
				},
				"api_key": {
					Type:        schema.TypeString,
					Required:    false,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_API_KEY", ""),
				},
				"api_secret": {
					Type:        schema.TypeString,
					Required:    false,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_API_SECRET", ""),
				},
				"authlete_version": {
					Type:        schema.TypeString,
					Required:    false,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_API_VERSION", "2"),
				},
			},

			ResourcesMap: map[string]*schema.Resource{
				"authlete_service": service(),
				"authlete_client":  client(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

type apiClient struct {
	// Add whatever fields, client or connection info, etc. here
	// you would need to setup to communicate with the upstream
	// API.
	// serverVersion      int
	apiServerId        string
	organizationId     string
	idpServer          string
	apiServer          string
	serviceOwnerKey    string
	serviceOwnerSecret string
	apiKey             string
	apiSecret          string
	authleteClient     *ClientWrapper
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
		apiServer := data.Get("api_server").(string)
		idpServer := data.Get("idp_server").(string)
		serviceOwnerKey := data.Get("service_owner_key").(string)
		serviceOwnerSecret := data.Get("service_owner_secret").(string)
		apiKey := data.Get("api_key").(string)
		apiSecret := data.Get("api_secret").(string)
		apiServerId := data.Get("api_server_id").(string)
		organizationId := data.Get("organization_id").(string)

		cnf := configureClient(authlete3.APIClient{}, p, apiServer, version)
		cnfIdp := configureClient(idp.APIClient{}, p, idpServer, version)

		apiClientOpenAPI := ClientWrapper{v3: authlete3.NewAPIClient(cnf.(*authlete3.Configuration)),
			idp: idp.NewAPIClient(cnfIdp.(*idp.Configuration))}
		return &apiClient{apiServer: apiServer, serviceOwnerKey: serviceOwnerKey,
			serviceOwnerSecret: serviceOwnerSecret, apiKey: apiKey, apiSecret: apiSecret,
			apiServerId: apiServerId, organizationId: organizationId,
			idpServer: idpServer, authleteClient: &apiClientOpenAPI}, nil

	}
}

type apiClientTypes interface {
	idp.APIClient | authlete.APIClient | authlete3.APIClient
}

func configureClient[K apiClientTypes](c K, p *schema.Provider, server string, version string) interface{} {
	if reflect.TypeOf(c) == reflect.TypeOf(authlete3.APIClient{}) {
		cnf := authlete3.NewConfiguration()
		cnf.UserAgent = p.UserAgent("terraform-provider-authlete", version)

		cnf.Servers[0].URL = server

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
		return cnf
	} else if reflect.TypeOf(c) == reflect.TypeOf(authlete.APIClient{}) {
		cnf := authlete.NewConfiguration()
		cnf.UserAgent = p.UserAgent("terraform-provider-authlete", version)

		cnf.Servers[0].URL = server

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
		return cnf
	}
	cnf := idp.NewConfiguration()
	cnf.UserAgent = p.UserAgent("terraform-provider-authlete", version)

	cnf.Servers[0].URL = server

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
	return cnf
}
