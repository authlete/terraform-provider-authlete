package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSupportedFrameworkSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(types.ServiceProfile_FAPI),
				string(types.ServiceProfile_OPEN_BANKING),
			}, false),
		},
	}
}

func mapSupportedFramework(vals *schema.Set) []types.ServiceProfile {

	values := make([]types.ServiceProfile, vals.Len())

	for i, v := range vals.List() {
		values[i] = types.ServiceProfile(v.(string))
	}

	return values
}
