package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
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
				string(authlete3.GRANTTYPE_AUTHORIZATION_CODE),
				string(authlete3.GRANTTYPE_IMPLICIT),
				string(authlete3.GRANTTYPE_PASSWORD),
				string(authlete3.GRANTTYPE_CLIENT_CREDENTIALS),
				string(authlete3.GRANTTYPE_REFRESH_TOKEN),
				string(authlete3.GRANTTYPE_CIBA),
				string(authlete3.GRANTTYPE_DEVICE_CODE),
				string(authlete3.GRANTTYPE_JWT_BEARER),
				string(authlete3.GRANTTYPE_TOKEN_EXCHANGE),
			}, false),
		},
	}
}
