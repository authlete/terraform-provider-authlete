package provider

import (
	authlete "github.com/authlete/openapi-for-go"
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

func mapTaggedValuesToDTO(entry []interface{}) []authlete.TaggedValue {
	var entries = []authlete.TaggedValue{}

	if entry != nil {
		for _, v := range entry {
			var keypair = v.(map[string]interface{})
			newTag := authlete.NewTaggedValue()
			newTag.SetTag(keypair["tag"].(string))
			newTag.SetValue(keypair["value"].(string))
			entries = append(entries, *newTag)
		}
	}
	return entries
}

func mapTaggedValuesFromDTO(pairs []authlete.TaggedValue) []interface{} {

	if pairs != nil {
		entries := make([]interface{}, len(pairs), len(pairs))

		for i, v := range pairs {
			newEntry := make(map[string]interface{})
			newEntry["tag"] = v.Tag
			newEntry["value"] = v.Value
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}
