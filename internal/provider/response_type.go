package provider

import (
	authlete "github.com/authlete/openapi-for-go"
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

func mapResponseTypesToDTO(vals []interface{}) []authlete.ResponseType {
	mapped := make([]authlete.ResponseType, len(vals))

	for i, v := range vals {
		mapped[i] = authlete.ResponseType(v.(string))
	}

	return mapped
}

func mapResponseTypesFromDTO(vals []authlete.ResponseType) []interface{} {

	if vals != nil {
		entries := make([]interface{}, len(vals), len(vals))
		for i, v := range vals {
			entries[i] = v
		}
		return entries
	}
	return make([]interface{}, 0)
}
