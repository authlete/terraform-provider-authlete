package provider

import (
	authlete "github.com/authlete/openapi-for-go"
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
