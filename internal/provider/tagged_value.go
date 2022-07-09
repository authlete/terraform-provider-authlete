package provider

import (
	authlete "github.com/authlete/openapi-for-go"
)

func mapTaggedValue(entry []interface{}) []authlete.TaggedValue {
	var entries = make([]authlete.TaggedValue, 0)

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
