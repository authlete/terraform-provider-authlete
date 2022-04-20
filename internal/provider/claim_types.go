package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSupportedClaimTypesSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(types.ClaimType_NORMAL),
				string(types.ClaimType_AGGREGATED),
				string(types.ClaimType_DISTRIBUTED),
			}, false),
		},
	}
}

func mapClaimTypes(vals []interface{}) []types.ClaimType {

	values := make([]types.ClaimType, len(vals))

	for i, v := range vals {
		values[i] = types.ClaimType(v.(string))
	}

	return values
}

func mapClaimTypesFromDTO(vals *[]types.ClaimType) []interface{} {

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
