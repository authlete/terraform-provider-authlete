package provider

import (
	"github.com/authlete/authlete-go-openapi"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createTaggedSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
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

func mapTaggedValue(entry []interface{}) []authlete.TaggedValue {
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
