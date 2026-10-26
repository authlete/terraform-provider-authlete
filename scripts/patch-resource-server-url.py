#!/usr/bin/env python3
"""Remove the per-resource server_url from authlete_service.

Speakeasy generates a server_url attribute on a resource whose operations
carry a path-level `servers:` block. Two of the service's do: /api/service and
/api/service/remove are hosted on Authlete's IdP rather than on a cluster.

The attribute is not merely redundant with the provider's idp_host, it is
dangerous. Setting it passes operations.WithServerURL, which sends the request
straight to that URL -- so the origin never matches the one
idpRoutingTransport watches for, and the transport neither redirects the
request nor injects organizationId and apiServerId. A practitioner who sets
server_url silently loses the routing that makes self-managed deployments work
at all, and the only visible symptom is an IdP error about a missing
apiServerId.

It is also the attribute the generated example sets, to login.authlete.com, so
the documentation teaches it.

There is no declarative way to drop it: it has no schema node for the overlay
to target, and removing the `servers:` block to stop it being generated would
take ServiceCreateIdpAPIServerList with it, which is where idp_routing.go
reads the default IdP origin from.

Removing an attribute is a breaking change, which is why this lands before
3.0.0 rather than after.

  patch-resource-server-url.py           apply
  patch-resource-server-url.py --check   verify, non-zero if it is back
"""
import re
import sys

FILE = "internal/provider/service_resource.go"

# Speakeasy writes the registry example from the schema, so it sets the
# attribute too. Left behind it is worse than redundant: the attribute no
# longer exists, so the example a newcomer copies fails with "Unsupported
# argument".
EXAMPLE = "examples/resources/authlete_service/resource.tf"
EXAMPLE_LINE = re.compile(r'\n\s*server_url\s+= "[^"]*"')

# Each is (description, pattern, occurrences). The counts are exact: a region
# that stops matching, or starts matching somewhere new, fails the run rather
# than leaving the file half edited.
REGIONS = [
    (
        "the model field",
        re.compile(r'\n\tServerURL\s+types\.String\s+`tfsdk:"server_url"`'),
        1,
    ),
    (
        "the schema attribute",
        re.compile(
            r'\n\t\t\t"server_url": schema\.StringAttribute\{'
            r'\n\t\t\t\tMarkdownDescription: `IDP Server`,'
            r"\n\t\t\t\tOptional:\s+true,"
            r"\n\t\t\t\},"
        ),
        1,
    ),
    (
        "the create and delete overrides",
        re.compile(
            r"\n\tif !data\.ServerURL\.IsNull\(\) && !data\.ServerURL\.IsUnknown\(\) \{"
            r"\n\t\tserverURL := data\.ServerURL\.ValueString\(\)"
            r"\n"
            r'\n\t\tif serverURL != "" \{'
            r"\n\t\t\t\w+ = append\(\w+, operations\.WithServerURL\(serverURL\)\)"
            r"\n\t\t\}"
            r"\n\t\}"
            r"\n"
        ),
        2,  # create and delete
    ),
]


def main():
    check = "--check" in sys.argv
    src = open(FILE).read()
    example = open(EXAMPLE).read()
    clean = "server_url" not in src and "data.ServerURL" not in src
    example_clean = not EXAMPLE_LINE.search(example)

    if clean and example_clean:
        if check:
            print("ok: authlete_service has no resource-level server_url")
        else:
            print("ok: already removed")
        return

    if clean and not example_clean:
        if check:
            print(
                f"error: {EXAMPLE} still sets server_url, which the resource no\n"
                "longer has, so the example fails with an unsupported argument.\n\n"
                "Run:\n\n  python3 scripts/patch-resource-server-url.py",
                file=sys.stderr,
            )
            sys.exit(1)
        open(EXAMPLE, "w").write(EXAMPLE_LINE.sub("", example, count=1))
        print(f"applied: removed server_url from {EXAMPLE}")
        return

    if check:
        print(
            "error: authlete_service has a server_url attribute again.\n\n"
            "Setting it sends service create and delete straight to that URL, so\n"
            "idp_routing.go never recognises the origin and never injects\n"
            "organizationId or apiServerId. A self-managed deployment then fails\n"
            "with an IdP error that names neither cause.\n\n"
            "A regeneration has most likely restored it. Run:\n\n"
            "  python3 scripts/patch-resource-server-url.py",
            file=sys.stderr,
        )
        sys.exit(1)

    for what, pattern, want in REGIONS:
        src, n = pattern.subn("", src)
        if n != want:
            print(
                f"error: expected to remove {what} {want} time(s), removed {n}.\n\n"
                "Speakeasy has most likely restructured the resource. Remove it by\n"
                "hand and update this script. Failing here is deliberate: a partial\n"
                "removal would not compile, and a silent skip would ship the\n"
                "attribute.",
                file=sys.stderr,
            )
            sys.exit(1)

    open(FILE, "w").write(src)
    print(f"applied: removed the resource-level server_url from {FILE}")

    if not example_clean:
        open(EXAMPLE, "w").write(EXAMPLE_LINE.sub("", example, count=1))
        print(f"applied: removed server_url from {EXAMPLE}")


if __name__ == "__main__":
    main()
