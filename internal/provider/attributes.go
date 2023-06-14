package provider

import (
	authlete "github.com/authlete/openapi-for-go/v2"
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createAttributeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"key": {Type: schema.TypeString,
					Required: true},
				"value": {Type: schema.TypeString,
					Required: true},
			},
		},
	}
}

func mapAttributesFromDTO(pairs []authlete.Pair) []interface{} {

	if pairs != nil {
		entries := make([]interface{}, len(pairs))

		for i, v := range pairs {
			newEntry := make(map[string]interface{})
			newEntry["key"] = v.Key
			newEntry["value"] = v.Value
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}

func mapAttributesFromDTOV3(pairs []authlete3.Pair) []interface{} {

	if pairs != nil {
		entries := make([]interface{}, len(pairs))

		for i, v := range pairs {
			newEntry := make(map[string]interface{})
			newEntry["key"] = v.Key
			newEntry["value"] = v.Value
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}
