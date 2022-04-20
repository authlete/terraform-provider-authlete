package provider

import (
	"github.com/authlete/authlete-go/dto"
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

func mapMtlsEndpoint(vals []interface{}) []dto.NamedUri {
	var entries = []dto.NamedUri{}

	for _, v := range vals {
		var keypair = v.(map[string]interface{})
		entries = append(entries, dto.NamedUri{
			Name: keypair["name"].(string),
			Uri:  keypair["uri"].(string),
		})
	}
	return entries
}

func mapMtlsEndpointfromDto(endpoints *[]dto.NamedUri) []interface{} {

	if endpoints != nil {
		entries := make([]interface{}, len(*endpoints), len(*endpoints))

		for i, v := range *endpoints {
			newEntry := make(map[string]interface{})
			newEntry["name"] = v.Name
			newEntry["uri"] = v.Uri
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}
