package provider

import (
	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createClientAuthSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Computed: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(authlete.CLIENTAUTHENTICATIONMETHOD_NONE),
				string(authlete.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_BASIC),
				string(authlete.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_POST),
				string(authlete.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_JWT),
				string(authlete.CLIENTAUTHENTICATIONMETHOD_PRIVATE_KEY_JWT),
				string(authlete.CLIENTAUTHENTICATIONMETHOD_TLS_CLIENT_AUTH),
				string(authlete.CLIENTAUTHENTICATIONMETHOD_SELF_SIGNED_TLS_CLIENT_AUTH),
			}, false),
		},
	}
}

func createClientAuthMethodSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Computed: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete.CLIENTAUTHENTICATIONMETHOD_NONE),
			string(authlete.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_BASIC),
			string(authlete.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_POST),
			string(authlete.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_JWT),
			string(authlete.CLIENTAUTHENTICATIONMETHOD_PRIVATE_KEY_JWT),
			string(authlete.CLIENTAUTHENTICATIONMETHOD_TLS_CLIENT_AUTH),
			string(authlete.CLIENTAUTHENTICATIONMETHOD_SELF_SIGNED_TLS_CLIENT_AUTH),
		}, false),
	}
}

func mapClientAuthMethodToDto(v interface{}) authlete.ClientAuthenticationMethod {
	return authlete.ClientAuthenticationMethod(v.(string))
}

func mapClientAuthMethods(auth []interface{}) []authlete.ClientAuthenticationMethod {

	authMethods := make([]authlete.ClientAuthenticationMethod, len(auth))

	for i, v := range auth {
		authMethods[i] = mapClientAuthMethodToDto(v)
	}

	return authMethods
}

func mapClientAuthMethodsFromDTO(vals []authlete.ClientAuthenticationMethod) []interface{} {

	if vals != nil {
		entries := make([]interface{}, len(vals), len(vals))
		for i, v := range vals {
			entries[i] = v
		}
		return entries
	}
	return make([]interface{}, 0)
}
