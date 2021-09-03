package provider

import (
	"github.com/authlete/authlete-go/types"
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
				string(types.DeliveryMode_POLL),
				string(types.DeliveryMode_PING),
				string(types.DeliveryMode_PUSH),
			}, false),
		},
	}
}

func mapBackchannelDelivery(vals *schema.Set) []types.DeliveryMode {

	values := make([]types.DeliveryMode, vals.Len())

	for i, v := range vals.List() {
		values[i] = types.DeliveryMode(v.(string))
	}

	return values
}
