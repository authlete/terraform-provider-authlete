#!/usr/bin/env python3
"""Keep deprecated attributes out of the registry example.

Speakeasy writes examples/resources/authlete_service/resource.tf from the
schema, setting every attribute the service has. That includes the ones the
API description marks deprecated, so the example a newcomer copies from the
registry produces a deprecation warning for each of them on the first plan.

The attributes still exist and still work, so there is nothing to remove from
the schema; the problem is only that the documentation teaches them. Removing
the lines from the example is the whole fix.

There is no declarative way to do it. The example is generated wholesale from
the schema and the overlay has no hook for which attributes it demonstrates,
so a regeneration puts the lines back.

  patch-deprecated-example.py           apply
  patch-deprecated-example.py --check   verify, non-zero if any are back
"""
import re
import sys

EXAMPLE = "examples/resources/authlete_service/resource.tf"

# Marked deprecated in the API description. Authlete 3.0 does not act on any of
# them, so an example that sets them teaches a setting with no behaviour behind
# it as though it were part of a working configuration.
DEPRECATED = [
    "authentication_callback_endpoint",
    "authentication_callback_api_key",
    "authentication_callback_api_secret",
    "clients_per_developer",
    "user_pin_length",
]


def line_pattern(attr):
    # The generator aligns the `=` across a block, so the gap before it varies.
    return re.compile(rf'\n[ \t]*{re.escape(attr)}[ \t]*=[^\n]*')


def main():
    check = "--check" in sys.argv[1:]
    src = open(EXAMPLE).read()

    present = [a for a in DEPRECATED if line_pattern(a).search(src)]

    if check:
        if present:
            print(
                "error: the registry example sets deprecated attributes again:\n\n"
                + "".join(f"  {a}\n" for a in present)
                + "\nAnyone copying the example from the registry gets a deprecation\n"
                "warning for each one on their first plan.\n\n"
                "A regeneration has most likely restored them. Run:\n\n"
                "  python3 scripts/patch-deprecated-example.py",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"ok: {EXAMPLE} sets no deprecated attributes")
        return

    if not present:
        print(f"ok: {EXAMPLE} already sets no deprecated attributes, nothing to do")
        return

    for attr in present:
        src, n = line_pattern(attr).subn("", src)
        if n != 1:
            print(
                f"error: expected to remove {attr} once, removed {n}.\n\n"
                "The example has most likely been restructured. Remove the line by\n"
                "hand and update this script. Failing here is deliberate: removing\n"
                "the wrong line would publish a broken example.",
                file=sys.stderr,
            )
            sys.exit(1)

    open(EXAMPLE, "w").write(src)
    print(f"applied: removed {len(present)} deprecated attribute(s) from {EXAMPLE}")


if __name__ == "__main__":
    main()
