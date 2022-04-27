package provider

import (
	"github.com/authlete/authlete-go/dto"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createTaggedValuesSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"tag": {Type: schema.TypeString,
					Required: true},
				"value": {Type: schema.TypeString,
					Required: true},
			},
		},
	}
}

func mapTaggedValuesToDTO(entry []interface{}) []dto.TaggedValue {
	var entries = []dto.TaggedValue{}

	if entry != nil {
		for _, v := range entry {
			var keypair = v.(map[string]interface{})
			entries = append(entries, dto.TaggedValue{
				Tag:   keypair["tag"].(string),
				Value: keypair["value"].(string),
			})
		}
	}
	return entries
}

func mapTaggedValuesFromDTO(pairs *[]dto.TaggedValue) []interface{} {

	if pairs != nil {
		entries := make([]interface{}, len(*pairs), len(*pairs))

		for i, v := range *pairs {
			newEntry := make(map[string]interface{})
			newEntry["tag"] = v.Tag
			newEntry["value"] = v.Value
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}
