package provider

import (
	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createGrantTypeSchema(optional bool) *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: optional,
		Required: !optional,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(authlete.GRANTTYPE_AUTHORIZATION_CODE),
				string(authlete.GRANTTYPE_IMPLICIT),
				string(authlete.GRANTTYPE_PASSWORD),
				string(authlete.GRANTTYPE_CLIENT_CREDENTIALS),
				string(authlete.GRANTTYPE_REFRESH_TOKEN),
				string(authlete.GRANTTYPE_CIBA),
				string(authlete.GRANTTYPE_DEVICE_CODE),
				string(authlete.GRANTTYPE_JWT_BEARER),
				string(authlete.GRANTTYPE_TOKEN_EXCHANGE),
			}, false),
		},
	}
}
