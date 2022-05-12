package provider

import (
	"github.com/authlete/authlete-go-openapi"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createUserCodeCharsetSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete.USERCODECHARSET_BASE20),
			string(authlete.USERCODECHARSET_NUMERIC),
		}, false),
	}
}

func mapUserCodeCharsets(val string) authlete.UserCodeCharset {

	return authlete.UserCodeCharset(val)
}

func mapUserCodeCharsetsFromDTO(val authlete.UserCodeCharset) string {
	return string(val)
}
