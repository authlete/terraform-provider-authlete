package stringplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.String = StringClearSupersededTLSClientAuthSanDNSPlanModifier{}

type StringClearSupersededTLSClientAuthSanDNSPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
// Body hand-written; Speakeasy generates this file once and does not
// overwrite it. The logic lives in internal/provider/planmodifiers.
func (v StringClearSupersededTLSClientAuthSanDNSPlanModifier) Description(ctx context.Context) string {
	return authletepm.ClearSupersededSubjectType("tls_client_auth_san_dns").Description(ctx)
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v StringClearSupersededTLSClientAuthSanDNSPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// Validate performs the plan modification.
func (v StringClearSupersededTLSClientAuthSanDNSPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	authletepm.ClearSupersededSubjectType("tls_client_auth_san_dns").PlanModifyString(ctx, req, resp)
}

func ClearSupersededTLSClientAuthSanDNS() planmodifier.String {
	return StringClearSupersededTLSClientAuthSanDNSPlanModifier{}
}
