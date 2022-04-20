package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createResponseTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: false,
		Required: true,
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

func mapResponseTypesToDTO(vals []interface{}) []types.ResponseType {
	mapped := make([]types.ResponseType, len(vals))

	for i, v := range vals {
		mapped[i] = types.ResponseType(v.(string))
	}

	return mapped
}

func mapResponseTypesFromDTO(vals *[]types.ResponseType) []interface{} {

	if vals != nil {
		entries := make([]interface{}, len(*vals), len(*vals))
		for i, v := range *vals {
			entries[i] = v
		}
		return entries
	}
	return make([]interface{}, 0)
}
