package listplanmodifier

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.List = ListSuppressDiffExplicitSuppressPlanModifier{}

// ListSuppressDiffExplicitSuppressPlanModifier delegates to the generated
// SuppressDiff modifier in this package, which takes a strategy argument the
// x-speakeasy-plan-modifiers extension cannot express. Naming the modifier
// SuppressDiff(ExplicitSuppress) in the overlay makes Speakeasy generate this
// file as a stub, once, and never overwrite it; the body is hand-written.
//
// It exists for service.metadata. Authlete fills that in after the service is
// created, so it holds a known value in state while planning as unknown, which
// marks the service as changing and every other computed attribute as unknown
// along with it.
//
// scripts/fill-suppress-diff-stub.py --check guards this against a stub that
// was regenerated from scratch.
type ListSuppressDiffExplicitSuppressPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
func (v ListSuppressDiffExplicitSuppressPlanModifier) Description(ctx context.Context) string {
	return SuppressDiff(ExplicitSuppress).Description(ctx)
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v ListSuppressDiffExplicitSuppressPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// PlanModifyList performs the plan modification.
func (v ListSuppressDiffExplicitSuppressPlanModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	SuppressDiff(ExplicitSuppress).PlanModifyList(ctx, req, resp)
}

func SuppressDiffExplicitSuppress() planmodifier.List {
	return ListSuppressDiffExplicitSuppressPlanModifier{}
}
