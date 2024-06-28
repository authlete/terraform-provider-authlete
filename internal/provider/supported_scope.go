package provider

import (
	idp "github.com/authlete/idp-api"
	authlete "github.com/authlete/openapi-for-go"
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createSupportedScopeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
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
					Computed: true,
					Required: false,
				},
				"descriptions": createTaggedValuesSchema(),
				"attributes":   createAttributeSchema(),
			},
		},
	}
}

func mapSupportedScopeToDTO(vals *schema.Set) []authlete.Scope {
	mapped := make([]authlete.Scope, vals.Len())

	for i, v := range vals.List() {
		var entry = v.(map[string]interface{})
		newScope := authlete.NewScope()
		newScope.SetName(entry["name"].(string))
		newScope.SetDescription(entry["description"].(string))
		newScope.SetDefaultEntry(entry["default_entry"].(bool))
		newScope.SetDescriptions(mapTaggedValue(entry["descriptions"].(*schema.Set).List()))
		newScope.SetAttributes(mapInterfaceListToStructList[authlete.Pair](entry["attributes"].(*schema.Set).List()))
		mapped[i] = *newScope
	}
	return mapped
}

func mapSupportedScopeToDTOV3(vals *schema.Set) []authlete3.Scope {
	mapped := make([]authlete3.Scope, vals.Len())

	for i, v := range vals.List() {
		var entry = v.(map[string]interface{})
		newScope := authlete3.NewScope()
		newScope.SetName(entry["name"].(string))
		newScope.SetDescription(entry["description"].(string))
		newScope.SetDefaultEntry(entry["default_entry"].(bool))
		newScope.SetDescriptions(mapTaggedValueV3(entry["descriptions"].(*schema.Set).List()))
		newScope.SetAttributes(mapInterfaceListToStructList[authlete3.Pair](entry["attributes"].(*schema.Set).List()))
		mapped[i] = *newScope
	}
	return mapped
}

func mapSupportedScopeToDTOIDP(vals *schema.Set) []idp.Scope {
	mapped := make([]idp.Scope, vals.Len())

	for i, v := range vals.List() {
		var entry = v.(map[string]interface{})
		newScope := idp.NewScope()
		newScope.SetName(entry["name"].(string))
		newScope.SetDescription(entry["description"].(string))
		newScope.SetDefaultEntry(entry["default_entry"].(bool))
		newScope.SetDescriptions(mapTaggedValueIDP(entry["descriptions"].(*schema.Set).List()))
		newScope.SetAttributes(mapInterfaceListToStructList[idp.Pair](entry["attributes"].(*schema.Set).List()))
		mapped[i] = *newScope
	}
	return mapped
}

func mapSupportedScopeFromDTO(data []interface{}, scopes []authlete.Scope) []interface{} {

	for _, remoteScope := range scopes {
		found := false
		for _, localScope := range data {
			localScopeObj := localScope.(map[string]interface{})
			localScopeName, ok := localScopeObj["name"].(string)
			if !ok {
				localScopeName = *localScopeObj["name"].(*string)
			}
			if *remoteScope.Name == localScopeName {
				found = true
				localScopeObj["default_entry"] = remoteScope.DefaultEntry
				localScopeObj["description"] = remoteScope.Description
				localScopeObj["descriptions"] = mapTaggedValuesFromDTO(remoteScope.Descriptions)
				localScopeObj["attributes"] = mapAttributesFromDTO(remoteScope.Attributes)
			}
		}
		if !found {
			newEntry := make(map[string]interface{})
			newEntry["name"] = remoteScope.Name
			newEntry["default_entry"] = remoteScope.DefaultEntry
			newEntry["description"] = remoteScope.Description
			newEntry["descriptions"] = mapTaggedValuesFromDTO(remoteScope.Descriptions)
			newEntry["attributes"] = mapAttributesFromDTO(remoteScope.Attributes)
			data = append(data, newEntry)
		}
	}
	for i, localScope := range data {
		found := false
		localScopeObj := localScope.(map[string]interface{})
		localScopeName, ok := localScopeObj["name"].(string)
		if !ok {
			localScopeName = *localScopeObj["name"].(*string)
		}
		for _, remoteScope := range scopes {
			if *(remoteScope.Name) == localScopeName {
				found = true
			}
		}
		if !found {
			data = append(data[:i], data[i+1:]...)
		}
	}
	return data
}

func mapSupportedScopeFromDTOV3(data []interface{}, scopes []authlete3.Scope) []interface{} {
	for _, remoteScope := range scopes {
		found := false
		for _, localScope := range data {
			localScopeObj := localScope.(map[string]interface{})
			if *(remoteScope.Name) == localScopeObj["name"].(string) {
				found = true
				localScopeObj["default_entry"] = remoteScope.DefaultEntry
				localScopeObj["description"] = remoteScope.Description
				localScopeObj["descriptions"] = mapTaggedValuesFromDTOV3(remoteScope.Descriptions)
				localScopeObj["attributes"] = mapAttributesFromDTOV3(remoteScope.Attributes)
			}
		}
		if !found {
			newEntry := make(map[string]interface{})
			newEntry["name"] = remoteScope.Name
			newEntry["default_entry"] = remoteScope.DefaultEntry
			newEntry["description"] = remoteScope.Description
			newEntry["descriptions"] = mapTaggedValuesFromDTOV3(remoteScope.Descriptions)
			newEntry["attributes"] = mapAttributesFromDTOV3(remoteScope.Attributes)
			data = append(data, newEntry)
		}
	}
	for i, localScope := range data {
		found := false
		localScopeObj := localScope.(map[string]interface{})
		for _, remoteScope := range scopes {
			if *(remoteScope.Name) == localScopeObj["name"].(string) {
				found = true
			}
		}
		if !found {
			data = append(data[:i], data[i+1:]...)
		}
	}
	return data
}

func mapSupportedScopeFromDTOIDP(data []interface{}, scopes []idp.Scope) []interface{} {
	for _, remoteScope := range scopes {
		found := false
		for _, localScope := range data {
			localScopeObj := localScope.(map[string]interface{})
			if *(remoteScope.Name) == localScopeObj["name"].(string) {
				found = true
				localScopeObj["default_entry"] = remoteScope.DefaultEntry
				localScopeObj["description"] = remoteScope.Description
				localScopeObj["descriptions"] = mapTaggedValuesFromDTOIDP(remoteScope.Descriptions)
				localScopeObj["attributes"] = mapAttributesFromDTOIDP(remoteScope.Attributes)
			}
		}
		if !found {
			newEntry := make(map[string]interface{})
			newEntry["name"] = remoteScope.Name
			newEntry["default_entry"] = remoteScope.DefaultEntry
			newEntry["description"] = remoteScope.Description
			newEntry["descriptions"] = mapTaggedValuesFromDTOIDP(remoteScope.Descriptions)
			newEntry["attributes"] = mapAttributesFromDTOIDP(remoteScope.Attributes)
			data = append(data, newEntry)
		}
	}
	for i, localScope := range data {
		found := false
		localScopeObj := localScope.(map[string]interface{})
		for _, remoteScope := range scopes {
			if *(remoteScope.Name) == localScopeObj["name"].(string) {
				found = true
			}
		}
		if !found {
			data = append(data[:i], data[i+1:]...)
		}
	}
	return data

}
