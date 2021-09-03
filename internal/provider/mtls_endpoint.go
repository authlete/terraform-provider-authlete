package provider

import (
	"github.com/authlete/authlete-go/dto"
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

func mapMtlsEndpoint(vals *schema.Set) []dto.NamedUri {
	var entries = []dto.NamedUri{}

	for _, v := range vals.List() {
		var keypair = v.(map[string]interface{})
		entries = append(entries, dto.NamedUri{
			Name: keypair["name"].(string),
			Uri:  keypair["uri"].(string),
		})
	}
	return entries
}
