package int32planmodifier

import (
	"context"

	fwInt32 "github.com/hashicorp/terraform-plugin-framework/resource/schema/int32planmodifier"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.Int32 = Int32UseStateForUnknownPlanModifier{}

type Int32UseStateForUnknownPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
func (v Int32UseStateForUnknownPlanModifier) Description(_ context.Context) string {
	return "this value is stable across updates, so it is not planned as unknown"
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v Int32UseStateForUnknownPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// Delegates to the framework's own UseStateForUnknown. Hand-written;
// Speakeasy generates this file once and does not overwrite it.
func (v Int32UseStateForUnknownPlanModifier) PlanModifyInt32(ctx context.Context, req planmodifier.Int32Request, resp *planmodifier.Int32Response) {
	fwInt32.UseStateForUnknown().PlanModifyInt32(ctx, req, resp)
}

func UseStateForUnknown() planmodifier.Int32 {
	return Int32UseStateForUnknownPlanModifier{}
}
