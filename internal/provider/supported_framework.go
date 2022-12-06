package provider

import (
	authlete "github.com/authlete/openapi-for-go"
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
				string(authlete.SERVICEPROFILE_FAPI),
				string(authlete.SERVICEPROFILE_OPEN_BANKING),
			}, false),
		},
	}
}

func mapSupportedFrameworkToDTO(vals []interface{}) []authlete.ServiceProfile {

	values := make([]authlete.ServiceProfile, len(vals))

	for i, v := range vals {
		values[i] = authlete.ServiceProfile(v.(string))
	}

	return values
}

func mapSupportedFrameworkFromDTO(vals []authlete.ServiceProfile) []interface{} {

	if vals != nil {
		entries := make([]interface{}, len(vals), len(vals))
		for i, v := range vals {
			entries[i] = v
		}
		return entries
	}
	return make([]interface{}, 0)
}
