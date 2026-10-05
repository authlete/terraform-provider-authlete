package stringplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.String = StringClearSupersededTLSClientAuthSubjectDnPlanModifier{}

type StringClearSupersededTLSClientAuthSubjectDnPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
// Body hand-written; Speakeasy generates this file once and does not
// overwrite it. The logic lives in internal/provider/planmodifiers.
func (v StringClearSupersededTLSClientAuthSubjectDnPlanModifier) Description(ctx context.Context) string {
	return authletepm.ClearSupersededSubjectType("tls_client_auth_subject_dn").Description(ctx)
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v StringClearSupersededTLSClientAuthSubjectDnPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// Validate performs the plan modification.
func (v StringClearSupersededTLSClientAuthSubjectDnPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	authletepm.ClearSupersededSubjectType("tls_client_auth_subject_dn").PlanModifyString(ctx, req, resp)
}

func ClearSupersededTLSClientAuthSubjectDn() planmodifier.String {
	return StringClearSupersededTLSClientAuthSubjectDnPlanModifier{}
}
