package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createGrantTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: false,
		Required: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(types.GrantType_AUTHORIZATION_CODE),
				string(types.GrantType_IMPLICIT),
				string(types.GrantType_PASSWORD),
				string(types.GrantType_CLIENT_CREDENTIALS),
				string(types.GrantType_REFRESH_TOKEN),
				string(types.GrantType_CIBA),
				string(types.GrantType_DEVICE_CODE),
			}, false),
		},
	}
}

func mapGrantTypesToDTO(vals []interface{}) []types.GrantType {

	values := make([]types.GrantType, len(vals))

	for i, v := range vals {
		values[i] = types.GrantType(v.(string))
	}

	return values
}

func mapGrantTypesFromDTO(vals *[]types.GrantType) []interface{} {

	var result = make([]interface{}, len(*vals))

	if vals != nil {
		for i, v := range *vals {
			var str string
			str = string(v)
			result[i] = str
		}
	}
	return result
}
