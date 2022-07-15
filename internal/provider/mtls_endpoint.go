package provider

import (
	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createMtlsEndpointSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {Type: schema.TypeString,
					Required: true},
				"uri": {Type: schema.TypeString,
					Required: true},
			},
		},
	}
}

func mapMtlsEndpoint(vals []interface{}) []authlete.NamedUri {
	var entries = make([]authlete.NamedUri, 0)

	for _, v := range vals {
		var keypair = v.(map[string]interface{})
		named := authlete.NewNamedUri()
		named.SetName(keypair["name"].(string))
		named.SetUri(keypair["uri"].(string))
		entries = append(entries, *named)
	}
	return entries
}

func mapMtlsEndpointFromDTO(endpoints []authlete.NamedUri) []interface{} {

	if endpoints != nil {
		entries := make([]interface{}, len(endpoints), len(endpoints))

		for i, v := range endpoints {
			newEntry := make(map[string]interface{})
			newEntry["name"] = v.Name
			newEntry["uri"] = v.Uri
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}
