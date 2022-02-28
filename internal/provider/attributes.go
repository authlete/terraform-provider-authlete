package provider

import (
	"github.com/authlete/authlete-go/dto"
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

func mapAttributes(entry *schema.Set) []dto.Pair {
	var entries = []dto.Pair{}

	if entry != nil {
		for _, v := range entry.List() {
			var keypair = v.(map[string]interface{})
			entries = append(entries, dto.Pair{
				Key:   keypair["key"].(string),
				Value: keypair["value"].(string),
			})
		}
	}
	return entries
}
