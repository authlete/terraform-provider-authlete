package provider

import (
	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createGrantTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: false,
		Required: true,
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
			}, false),
		},
	}
}

func mapGrantTypesToDTO(vals *schema.Set) []authlete.GrantType {

	values := make([]authlete.GrantType, vals.Len())

	for i, v := range vals.List() {
		values[i] = authlete.GrantType(v.(string))
	}

	return values
}

func mapGrantTypesFromDTO(vals []authlete.GrantType) []interface{} {

	var result = make([]interface{}, len(vals))

	if vals != nil {
		for i, v := range vals {
			var str string
			str = string(v)
			result[i] = str
		}
	}
	return result
}
