package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createClientAuthSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(types.ClientAuthMethod_NONE),
				string(types.ClientAuthMethod_CLIENT_SECRET_BASIC),
				string(types.ClientAuthMethod_CLIENT_SECRET_POST),
				string(types.ClientAuthMethod_CLIENT_SECRET_JWT),
				string(types.ClientAuthMethod_PRIVATE_KEY_JWT),
				string(types.ClientAuthMethod_TLS_CLIENT_AUTH),
				string(types.ClientAuthMethod_SELF_SIGNED_TLS_CLIENT_AUTH),
			}, false),
		},
	}
}

func mapClientAuthMethods(auth *schema.Set) []types.ClientAuthMethod {

	authMethods := make([]types.ClientAuthMethod, auth.Len())

	for i, v := range auth.List() {
		authMethods[i] = types.ClientAuthMethod(v.(string))
	}

	return authMethods
}
