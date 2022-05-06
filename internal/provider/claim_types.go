package provider

import (
	"github.com/authlete/authlete-go-openapi"
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
				string(authlete.CLAIMTYPE_NORMAL),
				string(authlete.CLAIMTYPE_AGGREGATED),
				string(authlete.CLAIMTYPE_DISTRIBUTED),
			}, false),
		},
	}
}

func mapClaimTypesToDTO(vals []interface{}) []authlete.ClaimType {

	values := make([]authlete.ClaimType, len(vals))

	for i, v := range vals {
		values[i] = authlete.ClaimType(v.(string))
	}

	return values
}

func mapClaimTypesFromDTO(vals []authlete.ClaimType) []interface{} {

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
