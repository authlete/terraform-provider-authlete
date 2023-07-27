package provider

import (
	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createVerifiedClaimsType() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete.VERIFIEDCLAIMSVALIDATIONSCHEMA_STANDARD),
			string(authlete.VERIFIEDCLAIMSVALIDATIONSCHEMA_STANDARDID_DOCUMENT),
			string(authlete.VERIFIEDCLAIMSVALIDATIONSCHEMA_NULL),
		}, false),
	}
}
