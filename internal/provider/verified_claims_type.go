package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createVerifiedClaimsType() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete3.VERIFIEDCLAIMSVALIDATIONSCHEMA_STANDARD),
			string(authlete3.VERIFIEDCLAIMSVALIDATIONSCHEMA_STANDARDID_DOCUMENT),
		}, false),
	}
}
