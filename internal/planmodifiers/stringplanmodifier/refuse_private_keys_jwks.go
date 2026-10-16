package stringplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/v3/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.String = StringRefusePrivateKeysJwksPlanModifier{}

// StringRefusePrivateKeysJwksPlanModifier refuses a private or
// symmetric key in a client's JWK Set, including one whose value is not known
// until apply.
//
// Body hand-written; Speakeasy generates this file once and does not overwrite
// it. The logic lives in internal/provider/planmodifiers/public_jwks.go.
type StringRefusePrivateKeysJwksPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
func (v StringRefusePrivateKeysJwksPlanModifier) Description(ctx context.Context) string {
	return authletepm.RefusePrivateKeysInJWKS().Description(ctx)
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v StringRefusePrivateKeysJwksPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// PlanModifyString performs the plan modification.
func (v StringRefusePrivateKeysJwksPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	authletepm.RefusePrivateKeysInJWKS().PlanModifyString(ctx, req, resp)
}

func RefusePrivateKeysJwks() planmodifier.String {
	return StringRefusePrivateKeysJwksPlanModifier{}
}
