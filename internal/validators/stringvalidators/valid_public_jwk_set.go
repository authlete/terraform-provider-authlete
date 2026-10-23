package stringvalidators

import (
	"context"

	"github.com/authlete/terraform-provider-authlete/v3/internal/provider/customtypes"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var _ validator.String = StringValidPublicJWKSetValidator{}

type StringValidPublicJWKSetValidator struct{}

// Description describes the validation in plain text formatting.
func (v StringValidPublicJWKSetValidator) Description(_ context.Context) string {
	return "TODO: add validator description"
}

// MarkdownDescription describes the validation in Markdown formatting.
func (v StringValidPublicJWKSetValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// Validate performs the validation.
//
// An attribute validator rather than the custom type's ValidateAttribute.
// The framework calls a custom type's ValidateAttribute on every read of the
// value, state included, so these checks would also run against a key set
// Authlete already stores: a set created before they existed, or one a client
// registered through DCR, would break every refresh. A validator sees
// configuration only, which is the whole intent.
//
// Body hand-written; Speakeasy generates this file once and does not
// overwrite it. The checks live in internal/provider/customtypes/jwks.go.
func (v StringValidPublicJWKSetValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	resp.Diagnostics.Append(customtypes.ValidateDocument(req.Path, req.ConfigValue.ValueString(), true)...)
}

func ValidPublicJWKSet() validator.String {
	return StringValidPublicJWKSetValidator{}
}
