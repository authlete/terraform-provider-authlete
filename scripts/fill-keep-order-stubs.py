#!/usr/bin/env python3
"""Fill the generated plan modifier stubs whose bodies we write.

Speakeasy writes one stub per named plan modifier the first time it sees it,
with a body that raises "TODO: implement". It does not overwrite the file
afterwards, so the body below survives regeneration. This script puts it back if
a stub is ever regenerated from scratch, and is idempotent otherwise.

The logic itself lives in internal/provider/planmodifiers/; these are thin
delegates, one per attribute, because that is the shape Speakeasy generates.

Two bodies. A stub named keep_order_by_name_* belongs to a list of objects and
delegates to the modifier that matches elements on their name attribute;
anything else is a list of strings and delegates to the whole-element one.
Filling a list of objects with the string body would compile and then discard
edits, so the distinction is made here rather than left to whoever reruns this.
"""
import glob
import os
import re
import sys

TEMPLATE = '''package listplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/v3/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.List = {T}{{}}

// {T} keeps the order already in state
// when the configuration lists the same elements.
//
// Body hand-written; Speakeasy generates this file once and does not overwrite
// it. The logic lives in internal/provider/planmodifiers/unordered_list.go.
type {T} struct{{}}

// Description describes the plan modification in plain text formatting.
func (v {T}) Description(ctx context.Context) string {{
	return authletepm.KeepOrderWhenUnchanged().Description(ctx)
}}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v {T}) MarkdownDescription(ctx context.Context) string {{
	return v.Description(ctx)
}}

// PlanModifyList performs the plan modification.
func (v {T}) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {{
	authletepm.KeepOrderWhenUnchanged().PlanModifyList(ctx, req, resp)
}}

func {F}() planmodifier.List {{
	return {T}{{}}
}}
'''

BY_NAME_TEMPLATE = '''package listplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/v3/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.List = {T}{{}}

// {T} keeps the order already in state
// when the configuration describes the same entries, matched on name.
//
// Body hand-written; Speakeasy generates this file once and does not overwrite
// it. The logic lives in
// internal/provider/planmodifiers/unordered_object_list.go.
type {T} struct{{}}

// Description describes the plan modification in plain text formatting.
func (v {T}) Description(ctx context.Context) string {{
	return authletepm.KeepOrderByKeyWhenSatisfied("name").Description(ctx)
}}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v {T}) MarkdownDescription(ctx context.Context) string {{
	return v.Description(ctx)
}}

// PlanModifyList performs the plan modification.
func (v {T}) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {{
	authletepm.KeepOrderByKeyWhenSatisfied("name").PlanModifyList(ctx, req, resp)
}}

func {F}() planmodifier.List {{
	return {T}{{}}
}}
'''

REFUSE_TEMPLATE = '''package stringplanmodifier

import (
	"context"

	authletepm "github.com/authlete/terraform-provider-authlete/v3/internal/provider/planmodifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

var _ planmodifier.String = {T}{{}}

// {T} refuses a private or
// symmetric key in a client's JWK Set, including one whose value is not known
// until apply.
//
// Body hand-written; Speakeasy generates this file once and does not overwrite
// it. The logic lives in internal/provider/planmodifiers/public_jwks.go.
type {T} struct{{}}

// Description describes the plan modification in plain text formatting.
func (v {T}) Description(ctx context.Context) string {{
	return authletepm.RefusePrivateKeysInJWKS().Description(ctx)
}}

// MarkdownDescription describes the plan modification in Markdown formatting.
func (v {T}) MarkdownDescription(ctx context.Context) string {{
	return v.Description(ctx)
}}

// PlanModifyString performs the plan modification.
func (v {T}) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {{
	authletepm.RefusePrivateKeysInJWKS().PlanModifyString(ctx, req, resp)
}}

func {F}() planmodifier.String {{
	return {T}{{}}
}}
'''

LIST_DIR = "internal/planmodifiers/listplanmodifier"
STRING_DIR = "internal/planmodifiers/stringplanmodifier"

# Each family: where the stubs live, how they are named, and the interface
# their generated marker line declares.
FAMILIES = [
    (LIST_DIR, "keep_order_*.go", "List"),
    (STRING_DIR, "refuse_private_keys_*.go", "String"),
]

check = "--check" in sys.argv

stubs = []
for directory, pattern, _ in FAMILIES:
    found = sorted(glob.glob(os.path.join(directory, pattern)))
    if not found:
        sys.exit(f"error: no {pattern} stubs in {directory}. The overlay entries "
                 "that declare them have most likely been removed.")
    stubs += found

todo = [p for p in stubs if "TODO" in open(p).read()]

if check:
    if todo:
        names = "\n".join("  " + os.path.basename(p) for p in todo)
        sys.exit(
            f"error: {len(todo)} of {len(stubs)} plan modifiers are "
            f"unimplemented stubs:\n\n{names}\n\n"
            "Those attributes raise \"TODO: implement\" on every plan instead of "
            "doing their job, so every plan touching them fails.\n\n"
            "A regeneration has most likely rewritten them. Run:\n\n"
            "  python3 scripts/fill-keep-order-stubs.py"
        )
    print(f"ok: all {len(stubs)} plan modifiers are implemented")
    sys.exit(0)

for path in todo:
    src = open(path).read()
    T = re.search(r"var _ planmodifier\.(?:List|String) = (\w+)\{\}", src).group(1)
    F = re.search(r"func (\w+)\(\) planmodifier\.(?:List|String)", src).group(1)
    base = os.path.basename(path)
    if base.startswith("refuse_private_keys_"):
        body = REFUSE_TEMPLATE
    elif base.startswith("keep_order_by_name_"):
        body = BY_NAME_TEMPLATE
    else:
        body = TEMPLATE
    open(path, "w").write(body.format(T=T, F=F))

print(f"filled {len(todo)} of {len(stubs)} stubs" if todo
      else f"ok: all {len(stubs)} stubs already implemented")
