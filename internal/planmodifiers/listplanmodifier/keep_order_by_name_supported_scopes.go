package listplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/v3/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.List = ListKeepOrderByNameSupportedScopesPlanModifier{}

// ListKeepOrderByNameSupportedScopesPlanModifier keeps the order already in state
// when the configuration describes the same entries, matched on name.
//
// Body hand-written; Speakeasy generates this file once and does not overwrite
// it. The logic lives in
// internal/provider/planmodifiers/unordered_object_list.go.
type ListKeepOrderByNameSupportedScopesPlanModifier struct{}

// Description describes the plan modification in plain text formatting.
func (v ListKeepOrderByNameSupportedScopesPlanModifier) Description(ctx context.Context) string {
	return authletepm.KeepOrderByKeyWhenSatisfied("name").Description(ctx)
}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v ListKeepOrderByNameSupportedScopesPlanModifier) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// PlanModifyList performs the plan modification.
func (v ListKeepOrderByNameSupportedScopesPlanModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	authletepm.KeepOrderByKeyWhenSatisfied("name").PlanModifyList(ctx, req, resp)
}

func KeepOrderByNameSupportedScopes() planmodifier.List {
	return ListKeepOrderByNameSupportedScopesPlanModifier{}
}
