package provider

import (
	authlete "github.com/authlete/openapi-for-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSignAlgorithmSchema() *schema.Schema {
	return &schema.Schema{
		Optional: true,
		Type:     schema.TypeString,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete.JWSALG_NONE),
			string(authlete.JWSALG_HS256),
			string(authlete.JWSALG_HS384),
			string(authlete.JWSALG_HS512),
			string(authlete.JWSALG_RS256),
			string(authlete.JWSALG_RS384),
			string(authlete.JWSALG_RS512),
			string(authlete.JWSALG_ES256),
			string(authlete.JWSALG_ES384),
			string(authlete.JWSALG_ES512),
			string(authlete.JWSALG_PS256),
			string(authlete.JWSALG_PS384),
			string(authlete.JWSALG_PS512),
		}, false),
	}
}

func mapSignAlgorithms(v string) authlete.JwsAlg {

	return authlete.JwsAlg(v)
}
