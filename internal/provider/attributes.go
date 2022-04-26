package provider

import (
	"github.com/authlete/authlete-go/dto"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createAttributeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
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

func mapAttributesToDTO(entry []interface{}) []dto.Pair {
	var entries = []dto.Pair{}

	if entry != nil {
		for _, v := range entry {
			var keypair = v.(map[string]interface{})
			entries = append(entries, dto.Pair{
				Key:   keypair["key"].(string),
				Value: keypair["value"].(string),
			})
		}
	}
	return entries
}

func mapAttributesFromDTO(pairs *[]dto.Pair) []interface{} {

	if pairs != nil {
		entries := make([]interface{}, len(*pairs), len(*pairs))

		for i, v := range *pairs {
			newEntry := make(map[string]interface{})
			newEntry["key"] = v.Key
			newEntry["value"] = v.Value
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}
