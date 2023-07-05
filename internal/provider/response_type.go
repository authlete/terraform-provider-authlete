package provider

import (
	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createResponseTypeSchema(optional bool) *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: optional,
		Required: !optional,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(authlete.RESPONSETYPE_NONE),
				string(authlete.RESPONSETYPE_CODE),
				string(authlete.RESPONSETYPE_TOKEN),
				string(authlete.RESPONSETYPE_ID_TOKEN),
				string(authlete.RESPONSETYPE_CODE_TOKEN),
				string(authlete.RESPONSETYPE_CODE_ID_TOKEN),
				string(authlete.RESPONSETYPE_ID_TOKEN_TOKEN),
				string(authlete.RESPONSETYPE_CODE_ID_TOKEN_TOKEN),
			}, false),
		},
	}
}
