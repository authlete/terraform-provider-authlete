package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
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
				string(authlete3.DISPLAY_PAGE),
				string(authlete3.DISPLAY_POPUP),
				string(authlete3.DISPLAY_TOUCH),
				string(authlete3.DISPLAY_WAP),
			}, false),
		},
	}
}
