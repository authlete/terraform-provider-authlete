package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
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
				string(authlete3.CLIENTAUTHENTICATIONMETHOD_NONE),
				string(authlete3.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_BASIC),
				string(authlete3.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_POST),
				string(authlete3.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_JWT),
				string(authlete3.CLIENTAUTHENTICATIONMETHOD_PRIVATE_KEY_JWT),
				string(authlete3.CLIENTAUTHENTICATIONMETHOD_TLS_CLIENT_AUTH),
				string(authlete3.CLIENTAUTHENTICATIONMETHOD_SELF_SIGNED_TLS_CLIENT_AUTH),
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
			string(authlete3.CLIENTAUTHENTICATIONMETHOD_NONE),
			string(authlete3.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_BASIC),
			string(authlete3.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_POST),
			string(authlete3.CLIENTAUTHENTICATIONMETHOD_CLIENT_SECRET_JWT),
			string(authlete3.CLIENTAUTHENTICATIONMETHOD_PRIVATE_KEY_JWT),
			string(authlete3.CLIENTAUTHENTICATIONMETHOD_TLS_CLIENT_AUTH),
			string(authlete3.CLIENTAUTHENTICATIONMETHOD_SELF_SIGNED_TLS_CLIENT_AUTH),
		}, false),
	}
}
