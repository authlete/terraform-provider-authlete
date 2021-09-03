package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createResponseTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(types.ResponseType_NONE),
				string(types.ResponseType_CODE),
				string(types.ResponseType_TOKEN),
				string(types.ResponseType_ID_TOKEN),
				string(types.ResponseType_CODE_TOKEN),
				string(types.ResponseType_CODE_ID_TOKEN),
				string(types.ResponseType_ID_TOKEN_TOKEN),
				string(types.ResponseType_CODE_ID_TOKEN_TOKEN),
			}, false),
		},
	}
}

func mapResponseTypes(vals *schema.Set) []types.ResponseType {
	mapped := make([]types.ResponseType, vals.Len())

	for i, v := range vals.List() {
		mapped[i] = types.ResponseType(v.(string))
	}

	return mapped
}
