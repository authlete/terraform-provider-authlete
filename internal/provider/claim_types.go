package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSupportedClaimTypesSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Computed: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(authlete3.CLAIMTYPE_NORMAL),
				string(authlete3.CLAIMTYPE_AGGREGATED),
				string(authlete3.CLAIMTYPE_DISTRIBUTED),
			}, false),
		},
	}
}
