package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSupportedDisplaySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
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

func mapSupportedDisplay(vals *schema.Set) []types.Display {

	values := make([]types.Display, vals.Len())

	for i, v := range vals.List() {
		values[i] = types.Display(v.(string))
	}

	return values
}
