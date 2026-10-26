#!/usr/bin/env bash
#
# Re-applies the hand edit in internal/provider/utils.go.
#
# debugResponse dumps the whole request and response, bodies included, into a
# diagnostic. Terraform prints a diagnostic on the terminal, on any API error,
# with debug logging off, so none of the TF_LOG masking in log_redaction.go
# applies to it: tflog never sees this string.
#
# Unmasked, a single 400 from Authlete prints the JWK Sets a service create
# sends, the client secret a client create returns, and whatever the customer
# put in http_headers. The migration guide documents a 400 that migrating
# customers hit routinely, so this is not a rare path.
#
# The edit wraps the return in redactDump. Speakeasy regenerates utils.go on
# every run, and the file compiles perfectly well without the wrapper, so
# losing it is silent.
#
#   ./scripts/patch-debug-response.sh           apply if missing
#   ./scripts/patch-debug-response.sh --check   exit non-zero if missing
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
FILE=internal/provider/utils.go

# Keyed on the call, not on the comment above it. A regeneration that kept the
# comment and dropped the code would otherwise read as healthy, which is the
# failure that got patch-provider.sh rewritten.
REQUIRED="return redactDump(fmt.Sprintf("
BARE='	return fmt.Sprintf("**Request**:\n%s\n**Response**:\n%s", string(dumpReq), string(dumpRes))'

CHECK=false
[[ "${1:-}" == "--check" ]] && CHECK=true

[[ -f "$FILE" ]] || { echo "error: $FILE not found" >&2; exit 1; }

if grep -qF "$REQUIRED" "$FILE"; then
  $CHECK && echo "ok: the debugResponse redaction is present"
  exit 0
fi

if $CHECK; then
  cat >&2 <<EOF
error: debugResponse no longer redacts its dump.

Every API error would print the full request and response to the terminal:
the JWK Sets sent by a service create, the client secret returned by a client
create, and any secret the customer set in http_headers. Debug logging does
not have to be on.

A regeneration has most likely dropped it. Run:

  ./scripts/patch-debug-response.sh
EOF
  exit 1
fi

grep -qF "$BARE" "$FILE" || {
  cat >&2 <<EOF
error: cannot apply the debugResponse patch -- the return statement has moved.

Expected to find:
$BARE

Speakeasy has most likely rewritten debugResponse. Re-apply the wrapper by
hand and update BARE in this script. Failing here is deliberate: skipping
silently would ship a provider that prints secrets on any API error.
EOF
  exit 1
}

python3 - "$FILE" <<'PY'
import sys
path = sys.argv[1]
bare = '\treturn fmt.Sprintf("**Request**:\\n%s\\n**Response**:\\n%s", string(dumpReq), string(dumpRes))'
wrapped = (
    "\t// hand-added, re-applied by scripts/patch-debug-response.sh. See\n"
    "\t// log_redaction.go: this dump goes into a diagnostic, which Terraform\n"
    "\t// prints on the terminal with debug logging off, so the TF_LOG masking\n"
    "\t// never sees it.\n"
    '\treturn redactDump(fmt.Sprintf("**Request**:\\n%s\\n**Response**:\\n%s", string(dumpReq), string(dumpRes)))'
)
src = open(path).read()
if bare not in src:
    sys.exit("anchor vanished between the check and the edit")
open(path, "w").write(src.replace(bare, wrapped, 1))
PY

command -v gofmt >/dev/null && gofmt -w "$FILE"
echo "applied: debugResponse now redacts its dump"
