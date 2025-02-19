package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSignAlgorithmSchema() *schema.Schema {
	return &schema.Schema{
		Optional: true,
		Type:     schema.TypeString,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete3.JWSALG_NONE),
			string(authlete3.JWSALG_HS256),
			string(authlete3.JWSALG_HS384),
			string(authlete3.JWSALG_HS512),
			string(authlete3.JWSALG_RS256),
			string(authlete3.JWSALG_RS384),
			string(authlete3.JWSALG_RS512),
			string(authlete3.JWSALG_ES256),
			string(authlete3.JWSALG_ES384),
			string(authlete3.JWSALG_ES512),
			string(authlete3.JWSALG_PS256),
			string(authlete3.JWSALG_PS384),
			string(authlete3.JWSALG_PS512),
		}, false),
	}
}
