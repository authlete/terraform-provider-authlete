package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createUserCodeCharsetSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(types.UserCodeCharset_BASE20),
			string(types.UserCodeCharset_NUMERIC),
		}, false),
	}
}

func mapUserCodeCharsets(val string) types.UserCodeCharset {

	return types.UserCodeCharset(val)
}
