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

func mapSupportedScopeFromDTO(scopes []authlete.Scope) []interface{} {

	var entries []interface{}
	for _, v := range scopes {
		if isStandardScope(v.GetName()) {
			continue
		}
		newEntry := make(map[string]interface{})
		newEntry["name"] = v.Name
		newEntry["default_entry"] = v.DefaultEntry
		newEntry["description"] = v.Description
		newEntry["descriptions"] = mapTaggedValuesFromDTO(v.Descriptions)
		newEntry["attributes"] = mapAttributesFromDTO(v.Attributes)
		entries = append(entries, newEntry)
	}
	return entries
}

func mapSupportedScopeFromDTOV3(scopes []authlete3.Scope) []interface{} {
	var entries []interface{}
	for _, v := range scopes {
		if isStandardScope(v.GetName()) {
			continue
		}
		newEntry := make(map[string]interface{})
		newEntry["name"] = v.Name
		newEntry["default_entry"] = v.DefaultEntry
		newEntry["description"] = v.Description
		newEntry["descriptions"] = mapTaggedValuesFromDTOV3(v.Descriptions)
		newEntry["attributes"] = mapAttributesFromDTOV3(v.Attributes)
		entries = append(entries, newEntry)
	}
	return entries
}

func mapSupportedScopeFromDTOIDP(scopes []idp.Scope) []interface{} {
	var entries []interface{}
	for _, v := range scopes {
		if isStandardScope(v.GetName()) {
			continue
		}
		newEntry := make(map[string]interface{})
		newEntry["name"] = v.Name
		newEntry["default_entry"] = v.DefaultEntry
		newEntry["description"] = v.Description
		newEntry["descriptions"] = mapTaggedValuesFromDTOIDP(v.Descriptions)
		newEntry["attributes"] = mapAttributesFromDTOIDP(v.Attributes)
		entries = append(entries, newEntry)
	}
	return entries
}

func isStandardScope(scopeName string) bool {
	standardScopes := []string{"address", "email", "openid", "offline_access", "phone", "profile"}
	for _, v := range standardScopes {
		if v == scopeName {
			return true
		}
	}
	return false
}
