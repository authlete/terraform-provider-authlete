package stringplanmodifier

import (
	"context"

	fwString "github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.String = StringUseStateForUnknownPlanModifier{}

type StringUseStateForUnknownPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
func (v StringUseStateForUnknownPlanModifier) Description(_ context.Context) string {
	return "this value is stable across updates, so it is not planned as unknown"
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v StringUseStateForUnknownPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// Delegates to the framework's own UseStateForUnknown. Hand-written;
// Speakeasy generates this file once and does not overwrite it.
func (v StringUseStateForUnknownPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	fwString.UseStateForUnknown().PlanModifyString(ctx, req, resp)
}

func UseStateForUnknown() planmodifier.String {
	return StringUseStateForUnknownPlanModifier{}
}
