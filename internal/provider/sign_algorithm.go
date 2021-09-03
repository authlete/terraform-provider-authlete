package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSignAlgorithmSchema() *schema.Schema {
	return &schema.Schema{
		Optional: true,
		Type:     schema.TypeString,
		ValidateFunc: validation.StringInSlice([]string{
			string(types.JWSAlg_NONE),
			string(types.JWSAlg_HS256),
			string(types.JWSAlg_HS384),
			string(types.JWSAlg_HS512),
			string(types.JWSAlg_RS256),
			string(types.JWSAlg_RS384),
			string(types.JWSAlg_RS512),
			string(types.JWSAlg_ES256),
			string(types.JWSAlg_ES384),
			string(types.JWSAlg_ES512),
			string(types.JWSAlg_PS256),
			string(types.JWSAlg_PS384),
			string(types.JWSAlg_PS512),
		}, false),
	}
}

func mapSignAlgorithms(v string) types.JWSAlg {

	return types.JWSAlg(v)
}
