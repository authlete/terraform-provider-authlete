package provider

import (
	authlete "github.com/authlete/openapi-for-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSupportedClaimTypesSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
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
