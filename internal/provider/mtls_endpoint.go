package provider

import (
	idp "github.com/authlete/idp-api"
	authlete "github.com/authlete/openapi-for-go"
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createMtlsEndpointSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
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

func mapMtlsEndpointV3(vals []interface{}) []authlete3.NamedUri {
	var entries = make([]authlete3.NamedUri, 0)

	for _, v := range vals {
		var keypair = v.(map[string]interface{})
		named := authlete3.NewNamedUri()
		named.SetName(keypair["name"].(string))
		named.SetUri(keypair["uri"].(string))
		entries = append(entries, *named)
	}
	return entries
}

func mapMtlsEndpointIDP(vals []interface{}) []idp.NamedUri {
	var entries = make([]idp.NamedUri, 0)

	for _, v := range vals {
		var keypair = v.(map[string]interface{})
		named := idp.NewNamedUri()
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

func mapMtlsEndpointFromDTOIDP(endpoints []idp.NamedUri) []interface{} {

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

func mapMtlsEndpointFromDTOV3(endpoints []authlete3.NamedUri) []interface{} {

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
