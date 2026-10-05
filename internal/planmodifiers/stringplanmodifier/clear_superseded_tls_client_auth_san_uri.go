package stringplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.String = StringClearSupersededTLSClientAuthSanURIPlanModifier{}

type StringClearSupersededTLSClientAuthSanURIPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
// Body hand-written; Speakeasy generates this file once and does not
// overwrite it. The logic lives in internal/provider/planmodifiers.
func (v StringClearSupersededTLSClientAuthSanURIPlanModifier) Description(ctx context.Context) string {
	return authletepm.ClearSupersededSubjectType("tls_client_auth_san_uri").Description(ctx)
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v StringClearSupersededTLSClientAuthSanURIPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// Validate performs the plan modification.
func (v StringClearSupersededTLSClientAuthSanURIPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	authletepm.ClearSupersededSubjectType("tls_client_auth_san_uri").PlanModifyString(ctx, req, resp)
}

func ClearSupersededTLSClientAuthSanURI() planmodifier.String {
	return StringClearSupersededTLSClientAuthSanURIPlanModifier{}
}
