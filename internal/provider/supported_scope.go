package provider

import (
	"github.com/authlete/authlete-go/dto"
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
				"attribute": {
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
				},
			},
		},
	}
}

func mapSupportedScope(vals *schema.Set) []dto.Scope {
	mapped := make([]dto.Scope, vals.Len())

	for i, v := range vals.List() {
		var entry = v.(map[string]interface{})

		mapped[i] = dto.Scope{
			Name:         entry["name"].(string),
			DefaultEntry: entry["default_entry"].(bool),
			Description:  entry["description"].(string),
			Attributes:   mapPair(entry["attribute"].(*schema.Set)),
		}
	}

	return mapped
}

func mapPair(entry *schema.Set) []dto.Pair {
	var entries = []dto.Pair{}

	for _, v := range entry.List() {
		var keypair = v.(map[string]interface{})
		entries = append(entries, dto.Pair{
			Key:   keypair["key"].(string),
			Value: keypair["value"].(string),
		})
	}

	return entries
}
