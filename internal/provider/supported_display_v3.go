//go:build v3
// +build v3

package provider

import (
	authlete "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSupportedDisplaySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Computed: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(authlete.DISPLAY_PAGE),
				string(authlete.DISPLAY_POPUP),
				string(authlete.DISPLAY_TOUCH),
				string(authlete.DISPLAY_WAP),
			}, false),
		},
	}
}

func mapSupportedDisplayToDTO(vals []interface{}) []authlete.Display {

	values := make([]authlete.Display, len(vals))

	for i, v := range vals {
		values[i] = authlete.Display(v.(string))
	}

	return values
}

func mapSupportedDisplayFromDTO(vals []authlete.Display) []interface{} {

	if vals != nil {
		entries := make([]interface{}, len(vals), len(vals))
		for i, v := range vals {
			entries[i] = v
		}
		return entries
	}
	return make([]interface{}, 0)
}