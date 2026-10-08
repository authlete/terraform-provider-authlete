#!/usr/bin/env bash
#
# Re-applies the read-path edit that lets an explicitly empty list round-trip.
#
# Seven list fields are marked nullable in the overlay so that leaving them out
# of a configuration omits them from the request and the server applies its
# defaults. That half works. The other half does not: when one of these lists is
# explicitly set to [], Authlete stores it as "nothing supported" and then omits
# the field from its response, and the generated read maps an absent field to
# null. State goes null, the configuration still says [], and the plan never
# settles.
#
# Absence is not ambiguous here. Every one of these seven has a non-empty server
# default, so a field missing from a response can only mean it was explicitly
# emptied -- a field left unset comes back populated with the default instead.
# That makes the correct read an empty list, not null.
#
# The fix belongs in the spec, as nullable on the request shape only. It cannot
# be written there: Authlete's OpenAPI document uses one `service` schema for
# both the request body and the response, so nullable applies to both directions
# or neither. Hence a patch.
#
#   ./scripts/patch-empty-lists.sh           apply if missing
#   ./scripts/patch-empty-lists.sh --check   exit non-zero if missing, change nothing
#
# Idempotent, and fails loudly if the generated shape it rewrites has moved,
# rather than silently producing a provider that drops empty lists again.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# file:Field pairs. Both the resource and the data source read through the same
# generated shape, and an empty list means the same thing in each.
SITES=(
  "internal/provider/service_resource_sdk.go:SupportedDisplays"
  "internal/provider/service_resource_sdk.go:SupportedGrantTypes"
  "internal/provider/service_resource_sdk.go:SupportedResponseTypes"
  "internal/provider/service_resource_sdk.go:SupportedTokenAuthMethods"
  "internal/provider/service_resource_sdk.go:SupportedPromptValues"
  "internal/provider/service_resource_sdk.go:SupportedClaimTypes"
  "internal/provider/service_data_source_sdk.go:SupportedDisplays"
  "internal/provider/service_data_source_sdk.go:SupportedGrantTypes"
  "internal/provider/service_data_source_sdk.go:SupportedResponseTypes"
  "internal/provider/service_data_source_sdk.go:SupportedTokenAuthMethods"
  "internal/provider/service_data_source_sdk.go:SupportedPromptValues"
  "internal/provider/service_data_source_sdk.go:SupportedClaimTypes"
  "internal/provider/client_resource_sdk.go:ResponseModes"
  "internal/provider/client_data_source_sdk.go:ResponseModes"
)

PATCHED='= []types.String{}'
ORIGINAL='= nil'

CHECK=false
[[ "${1:-}" == "--check" ]] && CHECK=true

missing=()
for site in "${SITES[@]}"; do
  file="${site%%:*}"
  field="${site##*:}"
  [[ -f "$file" ]] || { echo "error: $file not found" >&2; exit 1; }
  grep -qF "r.$field $PATCHED" "$file" || missing+=("$site")
done

if [[ ${#missing[@]} -eq 0 ]]; then
  $CHECK && echo "ok: the empty-list read patch is present at all ${#SITES[@]} sites"
  exit 0
fi

if $CHECK; then
  cat >&2 <<EOF
error: the empty-list read patch is missing at ${#missing[@]} of ${#SITES[@]} sites:

$(printf '  %s\n' "${missing[@]}")

Those reads map an absent list in a response back to null. A configuration that
sets one of these lists to [] will plan, apply, and then plan the same change
again forever, because state says null and the configuration says [].

A regeneration has most likely dropped it. Run:

  ./scripts/patch-empty-lists.sh
EOF
  exit 1
fi

python3 - "$PATCHED" "$ORIGINAL" "${missing[@]}" <<'PY'
import sys

patched, original = sys.argv[1], sys.argv[2]
sites = sys.argv[3:]

edits = {}
for site in sites:
    path, field = site.split(":")
    edits.setdefault(path, []).append(field)

for path, fields in edits.items():
    src = open(path).read()
    for field in fields:
        anchor = f"r.{field} {original}"
        count = src.count(anchor)
        if count != 1:
            sys.exit(
                f"error: cannot apply the empty-list patch to {path}.\n"
                f"Expected exactly one '{anchor}', found {count}.\n"
                "Speakeasy has most likely changed how a nullable list is read "
                "back. Re-apply the edit by hand and update SITES in "
                "scripts/patch-empty-lists.sh. Failing here is deliberate: "
                "silently skipping would ship a provider whose empty lists never "
                "settle."
            )
        src = src.replace(anchor, f"r.{field} {patched}", 1)
    open(path, "w").write(src)
PY

command -v gofmt >/dev/null && gofmt -w \
  internal/provider/service_resource_sdk.go \
  internal/provider/service_data_source_sdk.go \
  internal/provider/client_resource_sdk.go \
  internal/provider/client_data_source_sdk.go
echo "applied: re-inserted the empty-list read patch at ${#missing[@]} sites"
