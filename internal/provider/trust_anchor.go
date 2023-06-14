package provider

import (
	authlete "github.com/authlete/openapi-for-go/v2"
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func createTrustAnchorSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"entity_id": {Type: schema.TypeString,
					Required: true},
				"jwk": createJWKSchema(),
			},
		},
	}
}

func mapTrustAnchorToDTO(entry []interface{}, diags diag.Diagnostics) []authlete.TrustAnchor {
	var entries = make([]authlete.TrustAnchor, 0)

	if entry != nil {
		for _, v := range entry {
			var keypair = v.(map[string]interface{})
			newTag := authlete.NewTrustAnchor()
			newTag.SetEntityId(keypair["entity_id"].(string))
			jwks, _ := mapJWKS(keypair["jwk"].(*schema.Set).List(), diags)
			newTag.SetJwks(jwks)

			entries = append(entries, *newTag)
		}
	}
	return entries
}

func mapTrustAnchorToDTOV3(entry []interface{}, diags diag.Diagnostics) []authlete3.TrustAnchor {
	var entries = make([]authlete3.TrustAnchor, 0)

	if entry != nil {
		for _, v := range entry {
			var keypair = v.(map[string]interface{})
			newTag := authlete3.NewTrustAnchor()
			newTag.SetEntityId(keypair["entity_id"].(string))
			jwks, _ := mapJWKS(keypair["jwk"].(*schema.Set).List(), diags)
			newTag.SetJwks(jwks)

			entries = append(entries, *newTag)
		}
	}
	return entries
}

func mapTrustAnchorFromDTO(pairs []authlete.TrustAnchor) []interface{} {

	if pairs != nil {
		entries := make([]interface{}, len(pairs), len(pairs))

		for i, v := range pairs {
			newEntry := make(map[string]interface{})
			newEntry["entity_id"] = v.EntityId
			arr := make([]interface{}, 0, 0)
			jwk, _ := mapJWKFromDTO(arr, *v.Jwks)
			newEntry["jwk"] = jwk
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}

func mapTrustAnchorFromDTOV3(pairs []authlete3.TrustAnchor) []interface{} {

	if pairs != nil {
		entries := make([]interface{}, len(pairs), len(pairs))

		for i, v := range pairs {
			newEntry := make(map[string]interface{})
			newEntry["entity_id"] = v.EntityId
			arr := make([]interface{}, 0, 0)
			jwk, _ := mapJWKFromDTO(arr, *v.Jwks)
			newEntry["jwk"] = jwk
			entries[i] = newEntry
		}
		return entries
	}
	return make([]interface{}, 0)
}
