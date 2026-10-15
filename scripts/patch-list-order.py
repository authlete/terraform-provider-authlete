#!/usr/bin/env python3
"""Keep the stored order of the lists Authlete reorders, on read.

The KeepOrder plan modifiers stop those lists showing a diff, but Read still
overwrites state with the API's order. The configured order and the stored one
then differ, the resource is marked as changing, and every computed attribute
on it plans as unknown -- a plan that never settles, with the list no longer
the attribute that shows it.

This inserts two lines into each generated Read: one capturing the prior state
before the refresh, one restoring the order after it. The logic itself is in
internal/provider/list_order.go, which Speakeasy does not generate and does not
touch.

  patch-list-order.py           apply
  patch-list-order.py --check   verify, non-zero if any site is unpatched
"""
import re
import sys

# file -> (model type, restore function)
SITES = {
    "internal/provider/service_resource.go": ("ServiceResourceModel", "keepServiceListOrder"),
    "internal/provider/client_resource.go": ("ClientResourceModel", "keepClientListOrder"),
}

CAPTURE = "\tprevListOrder := *data // scripts/patch-list-order.py\n"


def read_block(src, model):
    """The Read function's refresh call, which is the one to patch.

    Create and Update also call RefreshFromSharedService, but they follow it
    with refreshPlan, which overwrites state with the planned values. The plan
    already carries the configured order, so only Read needs this.
    """
    m = re.search(r"func \(r \*\w+Resource\) Read\(.*?\n}\n", src, re.S)
    return m


def patch(path, model, fn, check):
    src = open(path).read()
    m = read_block(src, model)
    if not m:
        print(f"{path}: no Read function found", file=sys.stderr)
        return False
    body = m.group(0)

    if CAPTURE in body and fn + "(&prevListOrder, data)" in body:
        return True
    if check:
        print(f"{path}: Read does not restore list order", file=sys.stderr)
        return False

    refresh = "\tresp.Diagnostics.Append(data.RefreshFromSharedService(ctx, res.Service)...)\n"
    if model == "ClientResourceModel":
        refresh = re.search(r"\tresp\.Diagnostics\.Append\(data\.RefreshFromShared\w+\(ctx, [^)]*\)\.\.\.\)\n", body).group(0)
    if refresh not in body:
        print(f"{path}: refresh call not found in Read", file=sys.stderr)
        return False

    new_body = body.replace(refresh, CAPTURE + refresh, 1)
    # Restore after the error check that follows the refresh.
    tail = "\tif resp.Diagnostics.HasError() {\n\t\treturn\n\t}\n"
    idx = new_body.index(refresh) + len(refresh)
    rest = new_body[idx:]
    if not rest.lstrip("\n").startswith(tail.lstrip("\n")[:30]):
        pass
    after = rest.find(tail)
    if after == -1:
        print(f"{path}: could not place the restore call", file=sys.stderr)
        return False
    cut = idx + after + len(tail)
    new_body = (
        new_body[:cut]
        + f"\n\t{fn}(&prevListOrder, data) // scripts/patch-list-order.py\n"
        + new_body[cut:]
    )
    open(path, "w").write(src.replace(body, new_body, 1))
    return True


def main():
    check = "--check" in sys.argv
    ok = True
    for path, (model, fn) in SITES.items():
        ok = patch(path, model, fn, check) and ok
    if not ok:
        if check:
            print("\nRun scripts/patch-list-order.py to reapply.", file=sys.stderr)
        sys.exit(1)
    print(f"ok: list order is preserved on read in {len(SITES)} resources")


if __name__ == "__main__":
    main()
