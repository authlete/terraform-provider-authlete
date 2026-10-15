package listplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/v3/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.List = ListKeepOrderSupportedResponseTypesPlanModifier{}

// ListKeepOrderSupportedResponseTypesPlanModifier keeps the order already in state
// when the configuration lists the same elements.
//
// Body hand-written; Speakeasy generates this file once and does not overwrite
// it. The logic lives in internal/provider/planmodifiers/unordered_list.go.
type ListKeepOrderSupportedResponseTypesPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
func (v ListKeepOrderSupportedResponseTypesPlanModifier) Description(ctx context.Context) string {
	return authletepm.KeepOrderWhenUnchanged().Description(ctx)
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v ListKeepOrderSupportedResponseTypesPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// PlanModifyList performs the plan modification.
func (v ListKeepOrderSupportedResponseTypesPlanModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	authletepm.KeepOrderWhenUnchanged().PlanModifyList(ctx, req, resp)
}

func KeepOrderSupportedResponseTypes() planmodifier.List {
	return ListKeepOrderSupportedResponseTypesPlanModifier{}
}
