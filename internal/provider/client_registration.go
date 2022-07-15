package provider

import (
	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createClientRegistrationSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(authlete.CLIENTREGISTRATIONTYPE_AUTOMATIC),
				string(authlete.CLIENTREGISTRATIONTYPE_EXPLICIT),
			}, false),
		},
	}
}

func mapClientRegistrationToDTO(entry []interface{}) []authlete.ClientRegistrationType {
	var entries = make([]authlete.ClientRegistrationType, 0)

	if entry != nil {
		for _, v := range entry {
			newPair, _ := authlete.NewClientRegistrationTypeFromValue(v.(string))
			entries = append(entries, *newPair)
		}
	}
	return entries
}

func mapClientRegistrationFromDTO(registrationTypes []authlete.ClientRegistrationType) []interface{} {

	if registrationTypes != nil {
		entries := make([]interface{}, len(registrationTypes), len(registrationTypes))

		for i, v := range registrationTypes {
			newEntry := v.Ptr()
			entries[i] = string(*newEntry)
		}
		return entries
	}
	return make([]interface{}, 0)
}
