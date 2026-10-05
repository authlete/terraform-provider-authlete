package int64planmodifier

import (
	"context"

	fwInt64 "github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.Int64 = Int64UseStateForUnknownPlanModifier{}

type Int64UseStateForUnknownPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
func (v Int64UseStateForUnknownPlanModifier) Description(_ context.Context) string {
	return "this value is stable across updates, so it is not planned as unknown"
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v Int64UseStateForUnknownPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// Delegates to the framework's own UseStateForUnknown. Hand-written;
// Speakeasy generates this file once and does not overwrite it.
func (v Int64UseStateForUnknownPlanModifier) PlanModifyInt64(ctx context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	fwInt64.UseStateForUnknown().PlanModifyInt64(ctx, req, resp)
}

func UseStateForUnknown() planmodifier.Int64 {
	return Int64UseStateForUnknownPlanModifier{}
}
