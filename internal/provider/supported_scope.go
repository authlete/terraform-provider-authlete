package provider

import (
	"github.com/authlete/authlete-go-openapi"
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
				"descriptions": createTaggedValuesSchema(),
				"attribute":    createAttributeSchema(),
			},
		},
	}
}

func mapSupportedScopeToDTO(vals []interface{}) []authlete.Scope {
	mapped := make([]authlete.Scope, len(vals))

	for i, v := range vals {
		var entry = v.(map[string]interface{})
		newScope := authlete.NewScope()
		newScope.SetName(entry["name"].(string))
		newScope.SetDescription(entry["description"].(string))
		newScope.SetDefaultEntry(entry["default_entry"].(bool))
		newScope.SetDescriptions(mapTaggedValue(entry["descriptions"].([]interface{})))
		newScope.SetAttributes(mapAttributesToDTO(entry["attribute"].([]interface{})))
		mapped[i] = *newScope
	}
	return mapped
}

func mapSupportedScopeFromDTO(scopes []authlete.Scope) []interface{} {

	if scopes != nil {
		entries := make([]interface{}, len(scopes), len(scopes))

		for i, v := range scopes {
			newEntry := make(map[string]interface{})
			newEntry["name"] = v.Name
			newEntry["default_entry"] = v.DefaultEntry
			newEntry["description"] = v.Description
			newEntry["descriptions"] = mapTaggedValuesFromDTO(v.Descriptions)
			newEntry["attribute"] = mapAttributesFromDTO(v.Attributes)
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}
