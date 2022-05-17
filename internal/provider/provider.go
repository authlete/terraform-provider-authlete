package provider

import (
	"context"

	authlete "github.com/authlete/openapi-for-go"
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
					DefaultFunc: schema.EnvDefaultFunc("AUTHLETE_API_SERVER", "https://api.authlete.com/api"),
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
	api_server           string
	service_owner_key    string
	service_owner_secret string
	api_key              string
	api_secret           string
	authleteClient       *authlete.APIClient
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
		api_server := data.Get("api_server").(string)
		service_owner_key := data.Get("service_owner_key").(string)
		service_owner_secret := data.Get("service_owner_secret").(string)

		api_key := data.Get("api_key").(string)
		api_secret := data.Get("api_secret").(string)

		cnf := authlete.NewConfiguration()
		cnf.UserAgent = p.UserAgent("terraform-provider-authlete", version)
		cnf.Servers[0].URL = api_server

		apiClientOpenAPI := authlete.NewAPIClient(cnf)

		return &apiClient{api_server: api_server, service_owner_key: service_owner_key,
			service_owner_secret: service_owner_secret, api_key: api_key, api_secret: api_secret,
			authleteClient: apiClientOpenAPI}, nil
	}
}
