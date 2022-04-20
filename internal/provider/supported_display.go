package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSupportedDisplaySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(types.Display_PAGE),
				string(types.Display_POPUP),
				string(types.Display_TOUCH),
				string(types.Display_WAP),
			}, false),
		},
	}
}

func mapSupportedDisplay(vals []interface{}) []types.Display {

	values := make([]types.Display, len(vals))

	for i, v := range vals {
		values[i] = types.Display(v.(string))
	}

	return values
}

func mapSupportedDisplayFromDTO(vals *[]types.Display) []interface{} {

	if vals != nil {
		entries := make([]interface{}, len(*vals), len(*vals))
		for i, v := range *vals {
			entries[i] = v
		}
		return entries
	}
	return make([]interface{}, 0)
}
