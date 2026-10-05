package listvalidators

import (
	"context"
	"strconv"
	"strings"

	authletevalidators "github.com/authlete/terraform-provider-authlete/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ validator.List = ListValidEnumValuesValidator{}

type ListValidEnumValuesValidator struct{}

// Description describes the validation in plain text formatting.
func (v ListValidEnumValuesValidator) Description(_ context.Context) string {
	return "each element must be a value Authlete accepts for this attribute"
}

// MarkdownDescription describes the validation in Markdown formatting.
func (v ListValidEnumValuesValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// Delegates to internal/provider/validators, which checks against the enum types
// the SDK generates from the specification. Hand-written; Speakeasy generates
// this file once and does not overwrite it.
func (v ListValidEnumValuesValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	attribute := req.Path.String()
	if i := strings.LastIndex(attribute, "."); i >= 0 {
		attribute = attribute[i+1:]
	}

	var values []types.String
	if diags := req.ConfigValue.ElementsAs(ctx, &values, false); diags.HasError() {
		return
	}

	for i, value := range values {
		if value.IsNull() || value.IsUnknown() {
			continue
		}
		ok, known := authletevalidators.Accepts(attribute, value.ValueString())
		if !known || ok {
			continue
		}
		resp.Diagnostics.AddAttributeError(
			req.Path.AtListIndex(i),
			"Invalid value for "+attribute,
			strconv.Quote(value.ValueString())+" is not one of the values Authlete accepts "+
				"for this attribute. The permitted set is listed in the attribute documentation.\n\n"+
				"Without this check the value reaches Authlete unvalidated, which costs about a "+
				"minute of retries and then returns a generic 500 naming neither the attribute "+
				"nor the value.",
		)
	}
}

func ValidEnumValues() validator.List {
	return ListValidEnumValuesValidator{}
}
