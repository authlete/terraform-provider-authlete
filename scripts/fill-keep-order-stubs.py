#!/usr/bin/env python3
"""Fill the generated KeepOrder* plan modifier stubs.

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

DIR = "internal/planmodifiers/listplanmodifier"
check = "--check" in sys.argv

stubs = sorted(glob.glob(os.path.join(DIR, "keep_order_*.go")))
if not stubs:
    sys.exit(f"error: no KeepOrder stubs in {DIR}. The overlay entries that "
             "declare them have most likely been removed.")

todo = [p for p in stubs if "TODO" in open(p).read()]

if check:
    if todo:
        names = "\n".join("  " + os.path.basename(p) for p in todo)
        sys.exit(
            f"error: {len(todo)} of {len(stubs)} KeepOrder plan modifiers are "
            f"unimplemented stubs:\n\n{names}\n\n"
            "Those attributes raise \"TODO: implement\" on every plan instead of "
            "keeping the stored order, so a configuration listing the same values "
            "in a different order fails.\n\n"
            "A regeneration has most likely rewritten them. Run:\n\n"
            "  python3 scripts/fill-keep-order-stubs.py"
        )
    print(f"ok: all {len(stubs)} KeepOrder plan modifiers are implemented")
    sys.exit(0)

for path in todo:
    src = open(path).read()
    T = re.search(r"var _ planmodifier\.List = (\w+)\{\}", src).group(1)
    F = re.search(r"func (\w+)\(\) planmodifier\.List", src).group(1)
    body = BY_NAME_TEMPLATE if os.path.basename(path).startswith("keep_order_by_name_") else TEMPLATE
    open(path, "w").write(body.format(T=T, F=F))

print(f"filled {len(todo)} of {len(stubs)} stubs" if todo
      else f"ok: all {len(stubs)} stubs already implemented")
