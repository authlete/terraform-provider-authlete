package provider

import (
	"github.com/authlete/authlete-go/types"
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

func mapJWSAlg(v interface{}) types.JWSAlg {
	return types.JWSAlg(v.(string))
}

func createJWEAlgSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		ValidateFunc: validation.StringInSlice([]string{
			string(types.JWEAlg_RSA1_5),
			string(types.JWEAlg_RSA_OAEP),
			string(types.JWEAlg_RSA_OAEP_256),
			string(types.JWEAlg_A128KW),
			string(types.JWEAlg_A192KW),
			string(types.JWEAlg_A256KW),
			string(types.JWEAlg_DIR),
			string(types.JWEAlg_ECDH_ES),
			string(types.JWEAlg_ECDH_ES_A128KW),
			string(types.JWEAlg_ECDH_ES_A192KW),
			string(types.JWEAlg_ECDH_ES_A256KW),
			string(types.JWEAlg_A128GCMKW),
			string(types.JWEAlg_A192GCMKW),
			string(types.JWEAlg_A256GCMKW),
			string(types.JWEAlg_PBES2_HS256_A128KW),
			string(types.JWEAlg_PBES2_HS384_A192KW),
			string(types.JWEAlg_PBES2_HS512_A256KW),
		}, false),
	}
}

func mapJWEAlg(v interface{}) types.JWEAlg {
	return types.JWEAlg(v.(string))
}

func createJWEEncSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		ValidateFunc: validation.StringInSlice([]string{
			string(types.JWEEnc_A128CBC_HS256),
			string(types.JWEEnc_A192CBC_HS384),
			string(types.JWEEnc_A256CBC_HS512),
			string(types.JWEEnc_A128GCM),
			string(types.JWEEnc_A192GCM),
			string(types.JWEEnc_A256GCM),
		}, false)}
}
func mapJWEEnc(v interface{}) types.JWEEnc {
	return types.JWEEnc(v.(string))
}
