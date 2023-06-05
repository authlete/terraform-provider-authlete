package provider

import (
	authlete "github.com/authlete/openapi-for-go/v2"
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

func createJWEAlgSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete.JWEALG_RSA1_5),
			string(authlete.JWEALG_RSA_OAEP),
			string(authlete.JWEALG_RSA_OAEP_256),
			string(authlete.JWEALG_A128_KW),
			string(authlete.JWEALG_A192_KW),
			string(authlete.JWEALG_A256_KW),
			string(authlete.JWEALG_DIR),
			string(authlete.JWEALG_ECDH_ES),
			string(authlete.JWEALG_ECDH_ES_A128_KW),
			string(authlete.JWEALG_ECDH_ES_A192_KW),
			string(authlete.JWEALG_ECDH_ES_A256_KW),
			string(authlete.JWEALG_A128_GCMKW),
			string(authlete.JWEALG_A192_GCMKW),
			string(authlete.JWEALG_A256_GCMKW),
			string(authlete.JWEALG_PBES2_HS256_A128_KW),
			string(authlete.JWEALG_PBES2_HS384_A192_KW),
			string(authlete.JWEALG_PBES2_HS512_A256_KW),
		}, false),
	}
}

func createJWEEncSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete.JWEENC_A128_CBC_HS256),
			string(authlete.JWEENC_A192_CBC_HS384),
			string(authlete.JWEENC_A256_CBC_HS512),
			string(authlete.JWEENC_A128_GCM),
			string(authlete.JWEENC_A192_GCM),
			string(authlete.JWEENC_A256_GCM),
		}, false)}
}
func mapJWEEnc(v interface{}) authlete.JweEnc {
	return authlete.JweEnc(v.(string))
}
