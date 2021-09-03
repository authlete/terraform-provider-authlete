package provider

import (
	"github.com/authlete/authlete-go/dto"
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSNSSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(types.Sns_FACEBOOK),
			}, false),
		},
	}
}

func createSNSCredentialsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(types.Sns_FACEBOOK),
			}, false),
		},
	}
}

func mapSNS(vals *schema.Set) []types.Sns {

	values := make([]types.Sns, vals.Len())

	for i, v := range vals.List() {
		values[i] = types.Sns(v.(string))
	}

	return values
}

func mapSNSCredentials(vals *schema.Set) []dto.SnsCredentials {
	values := make([]dto.SnsCredentials, vals.Len())

	for i, v := range vals.List() {
		values[i] = dto.SnsCredentials{ApiKey: v.(string)}
	}

	return values
}
