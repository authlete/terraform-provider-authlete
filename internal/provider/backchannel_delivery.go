package provider

import (
	authlete "github.com/authlete/openapi-for-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createBackchannelDeliverySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(authlete.DELIVERYMODE_POLL),
				string(authlete.DELIVERYMODE_PING),
				string(authlete.DELIVERYMODE_PUSH),
			}, false),
		},
	}
}

func createDeliveryModeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		Computed: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete.DELIVERYMODE_POLL),
			string(authlete.DELIVERYMODE_PING),
			string(authlete.DELIVERYMODE_PUSH),
		}, false),
	}
}

func mapBackchannelDeliveryFromDTO(vals []authlete.DeliveryMode) []interface{} {

	if vals != nil {
		entries := make([]interface{}, len(vals), len(vals))
		for i, v := range vals {
			entries[i] = v
		}
		return entries
	}
	return make([]interface{}, 0)
}
