package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createUserCodeCharsetSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete3.USERCODECHARSET_BASE20),
			string(authlete3.USERCODECHARSET_NUMERIC),
		}, false),
	}
}
