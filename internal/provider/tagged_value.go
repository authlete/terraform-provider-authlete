package provider

import (
	idp "github.com/authlete/idp-api"
	authlete3 "github.com/authlete/openapi-for-go/v3"
)

func mapTaggedValueV3(entry []interface{}) []authlete3.TaggedValue {
	var entries = make([]authlete3.TaggedValue, 0)

	if entry != nil {
		for _, v := range entry {
			var keypair = v.(map[string]interface{})
			newTag := authlete3.NewTaggedValue()
			newTag.SetTag(keypair["tag"].(string))
			newTag.SetValue(keypair["value"].(string))
			entries = append(entries, *newTag)
		}
	}
	return entries
}

func mapTaggedValueIDP(entry []interface{}) []idp.TaggedValue {
	var entries = make([]idp.TaggedValue, 0)

	if entry != nil {
		for _, v := range entry {
			var keypair = v.(map[string]interface{})
			newTag := idp.NewTaggedValue()
			newTag.SetTag(keypair["tag"].(string))
			newTag.SetValue(keypair["value"].(string))
			entries = append(entries, *newTag)
		}
	}
	return entries
}
