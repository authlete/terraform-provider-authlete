package provider

import (
	"github.com/authlete/authlete-go/dto"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createSupportedScopeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
				},
				"default_entry": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},
				"description": {
					Type:     schema.TypeString,
					Optional: true,
					Required: false,
				},
				"attribute": createAttributeSchema(),
			},
		},
	}
}

func mapSupportedScope(vals []interface{}) []dto.Scope {
	mapped := make([]dto.Scope, len(vals))

	for i, v := range vals {
		var entry = v.(map[string]interface{})
		mapped[i] = dto.Scope{
			Name:         entry["name"].(string),
			DefaultEntry: entry["default_entry"].(bool),
			Description:  entry["description"].(string),
			Attributes:   mapAttributestoDto(entry["attribute"].([]interface{})),
		}
	}
	return mapped
}

func mapSupportedScopefromDto(scopes *[]dto.Scope) []interface{} {

	if scopes != nil {
		entries := make([]interface{}, len(*scopes), len(*scopes))

		for i, v := range *scopes {
			newEntry := make(map[string]interface{})
			newEntry["name"] = v.Name
			newEntry["default_entry"] = v.DefaultEntry
			newEntry["description"] = v.Description
			newEntry["attribute"] = mapAttributesfromDto(&v.Attributes)
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}
