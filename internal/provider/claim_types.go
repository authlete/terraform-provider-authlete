package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSupportedClaimTypesSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
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

func mapClaimTypes(vals *schema.Set) []types.ClaimType {

	values := make([]types.ClaimType, vals.Len())

	for i, v := range vals.List() {
		values[i] = types.ClaimType(v.(string))
	}

	return values
}
