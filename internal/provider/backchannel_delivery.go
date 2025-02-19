package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
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
				string(authlete3.DELIVERYMODE_POLL),
				string(authlete3.DELIVERYMODE_PING),
				string(authlete3.DELIVERYMODE_PUSH),
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
			string(authlete3.DELIVERYMODE_POLL),
			string(authlete3.DELIVERYMODE_PING),
			string(authlete3.DELIVERYMODE_PUSH),
		}, false),
	}
}
