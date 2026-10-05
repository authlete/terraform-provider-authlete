package stringplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.String = StringClearSupersededTLSClientAuthSanEmailPlanModifier{}

type StringClearSupersededTLSClientAuthSanEmailPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
// Body hand-written; Speakeasy generates this file once and does not
// overwrite it. The logic lives in internal/provider/planmodifiers.
func (v StringClearSupersededTLSClientAuthSanEmailPlanModifier) Description(ctx context.Context) string {
	return authletepm.ClearSupersededSubjectType("tls_client_auth_san_email").Description(ctx)
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v StringClearSupersededTLSClientAuthSanEmailPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// Validate performs the plan modification.
func (v StringClearSupersededTLSClientAuthSanEmailPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	authletepm.ClearSupersededSubjectType("tls_client_auth_san_email").PlanModifyString(ctx, req, resp)
}

func ClearSupersededTLSClientAuthSanEmail() planmodifier.String {
	return StringClearSupersededTLSClientAuthSanEmailPlanModifier{}
}
