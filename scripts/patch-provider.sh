#!/usr/bin/env bash
#
# Re-applies the one hand edit in internal/provider/provider.go.
#
# Speakeasy regenerates provider.go on every run. Our single edit -- the line
# that wraps the generated HTTP transport so IdP-bound requests reach the
# customer's own host and carry the ids the IdP needs -- survives through the
# persistentEdits three-way merge. That merge is reliable but not guaranteed: a
# conflict fails loudly, but a mis-set baseline can drop the edit quietly, and
# the file still compiles without it.
#
# This script puts it back. It is idempotent, so it is safe to run at any time,
# and it exits non-zero if the anchor it inserts after has disappeared -- which
# would mean Speakeasy restructured Configure and the patch needs rewriting,
# rather than silently producing an unpatched provider.
#
#   ./scripts/patch-provider.sh           apply if missing
#   ./scripts/patch-provider.sh --check   exit non-zero if missing, change nothing
#
# Mirrors scripts/patch-root-export.mjs in authlete/authlete-typescript-sdk.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
FILE=internal/provider/provider.go
MARKER="hand-added, see idp_routing.go"
ANCHOR="	httpClient.Transport = NewProviderHTTPTransport(providerHTTPTransportOpts)"

CHECK=false
[[ "${1:-}" == "--check" ]] && CHECK=true

[[ -f "$FILE" ]] || { echo "error: $FILE not found" >&2; exit 1; }

if grep -qF "$MARKER" "$FILE"; then
  $CHECK && echo "ok: provider.go patch is present"
  exit 0
fi

if $CHECK; then
  cat >&2 <<EOF
error: the provider.go patch is missing.

The line wrapping the HTTP transport is gone, so idp_host and organization_id
would be accepted and silently ignored: service create and delete would go to
Authlete's shared cloud regardless of configuration.

A regeneration has most likely dropped it. Run:

  ./scripts/patch-provider.sh
EOF
  exit 1
fi

grep -qF "$ANCHOR" "$FILE" || {
  cat >&2 <<EOF
error: cannot apply the provider.go patch -- anchor not found.

Expected to insert after:
$ANCHOR

Speakeasy has most likely restructured Configure. Re-apply the edit by hand and
update ANCHOR in this script. Failing here is deliberate: silently skipping
would ship a provider that ignores idp_host and organization_id.
EOF
  exit 1
}

python3 - "$FILE" "$ANCHOR" <<'PY'
import sys
path, anchor = sys.argv[1], sys.argv[2]
patch = '''
	// hand-added, see idp_routing.go -- the only edit to this generated file,
	// re-applied by scripts/patch-provider.sh.
	// idp_host and organization_id are declared as x-speakeasy-globals in the
	// overlay, so their attribute and struct field are generated; this is what
	// puts them to work, by wrapping the transport so IdP-bound requests reach
	// the customer's own host and carry the ids the IdP needs.
	idpHost := data.IdpHost.ValueString()
	if idpHost == "" {
		idpHost = os.Getenv("AUTHLETE_IDP_HOST")
	}
	organizationID := data.OrganizationID.ValueInt64()
	if organizationID == 0 {
		organizationID = OrganizationIDFromEnv()
	}
	// api_server_id: explicit configuration first, then the environment, and
	// only then the built-in cluster map. Deployments not on a public cluster --
	// Dedicated Cloud, On-Premise, pre-production -- are not in the map and must
	// supply it, or the IdP rejects create and delete with an apiServerId error.
	apiServerID := data.APIServerID.ValueInt64()
	if apiServerID == 0 {
		apiServerID = APIServerIDFromEnv()
	}
	if apiServerID == 0 {
		apiServerID, _ = APIServerIDForServerURL(serverUrl)
	}
	httpClient.Transport = NewIdpRoutingTransport(idpHost, apiServerID, organizationID, httpClient.Transport)
'''
src = open(path).read()
src = src.replace(anchor + "\n", anchor + "\n" + patch, 1)
open(path, "w").write(src)
PY

command -v gofmt >/dev/null && gofmt -w "$FILE"
echo "applied: re-inserted the provider.go transport patch"
