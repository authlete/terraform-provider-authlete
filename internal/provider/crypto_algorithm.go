package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createJWSAlgSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		Computed: true,
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

func createJWEAlgSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete3.JWEALG_RSA1_5),
			string(authlete3.JWEALG_RSA_OAEP),
			string(authlete3.JWEALG_RSA_OAEP_256),
			string(authlete3.JWEALG_A128_KW),
			string(authlete3.JWEALG_A192_KW),
			string(authlete3.JWEALG_A256_KW),
			string(authlete3.JWEALG_DIR),
			string(authlete3.JWEALG_ECDH_ES),
			string(authlete3.JWEALG_ECDH_ES_A128_KW),
			string(authlete3.JWEALG_ECDH_ES_A192_KW),
			string(authlete3.JWEALG_ECDH_ES_A256_KW),
			string(authlete3.JWEALG_A128_GCMKW),
			string(authlete3.JWEALG_A192_GCMKW),
			string(authlete3.JWEALG_A256_GCMKW),
			string(authlete3.JWEALG_PBES2_HS256_A128_KW),
			string(authlete3.JWEALG_PBES2_HS384_A192_KW),
			string(authlete3.JWEALG_PBES2_HS512_A256_KW),
		}, false),
	}
}

func createJWEEncSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete3.JWEENC_A128_CBC_HS256),
			string(authlete3.JWEENC_A192_CBC_HS384),
			string(authlete3.JWEENC_A256_CBC_HS512),
			string(authlete3.JWEENC_A128_GCM),
			string(authlete3.JWEENC_A192_GCM),
			string(authlete3.JWEENC_A256_GCM),
		}, false)}
}
