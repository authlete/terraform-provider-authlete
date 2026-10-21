#!/usr/bin/env bash
#
# Exercise the locally built terraform-provider-authlete without publishing it.
#
#   ./run.sh validate    # provider loads, config and schema are consistent (no API calls, no token)
#   ./run.sh plan        # default; shows what would be created (no API calls for new resources)
#   ./run.sh apply       # CREATES A REAL SERVICE AND CLIENT in your Authlete org
#   ./run.sh destroy     # deletes what apply created
#   ./run.sh import      # create a service, import it, and assert the plan is clean
#   ./run.sh reorder     # reordering a list already in state must plan nothing
#   ./run.sh gone        # only a real deletion may drop a resource from state
#   ./run.sh statekeys   # keys read back from Authlete must never be rejected
#   ./run.sh show        # print current state
#
# Terraform finds the Authlete provider through a dev_overrides block written to
# a throwaway CLI config in this directory. Your ~/.terraformrc is never touched.
# hashicorp/tls still comes from the registry, so the first run does an init.
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

REPO_ROOT="$(cd .. && pwd)"
TESTING_DIR="$PWD"
BIN_DIR="$PWD/.provider-bin"
TFRC="$PWD/.terraformrc.dev"
MODE="${1:-plan}"

# Which CLI to drive. OpenTofu implements the same plugin protocol as
# Terraform, so the same provider binary, the same configuration and the same
# dev_overrides file work under either. Set TF_BIN=tofu to run everything here
# against OpenTofu instead.
TF="${TF_BIN:-terraform}"

# An X25519 key for the service's JWK Set. hashicorp/tls cannot generate one,
# so the key comes from openssl, exactly as the migration guide tells a user to
# make it. The openssl macOS ships is LibreSSL, which has no X25519, so this is
# allowed to fail: main.tf treats an empty path as "one key fewer" rather than
# as an error, and the run says which happened.
#
# Gitignored through *.pem, so the key never reaches the repository.
ensure_x25519_key() {
  local out="$TESTING_DIR/x25519.pem"

  if [[ -s "$out" ]]; then
    X25519_PEM="$out"
    return
  fi
  if openssl genpkey -algorithm X25519 -out "$out" 2>/dev/null; then
    say "Generated an X25519 key for the service's JWK Set."
    X25519_PEM="$out"
    return
  fi

  rm -f "$out"
  X25519_PEM=""
  warn "openssl cannot generate X25519 here, so that key is left out of the run.
  The macOS system openssl is LibreSSL, which does not support it. Install a
  real OpenSSL and put it ahead on PATH to cover the X25519 path too."
}

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Local credentials, if present. Gitignored; see README. Anything already in the
# environment wins, so you can override a single value for one run.
if [[ -f .env.local ]]; then
  _pre_token="${AUTHLETE_TOKEN:-}"
  # shellcheck disable=SC1091
  source .env.local
  [[ -n "$_pre_token" ]] && AUTHLETE_TOKEN="$_pre_token"
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
command -v "$TF" >/dev/null 2>&1 || die \
  "$TF not found on PATH. Install it with:
    terraform  brew install hashicorp/tap/terraform
    tofu       brew install opentofu
  (terraform is the same dependency that makes 'go generate' fail during generation.)"
command -v go >/dev/null 2>&1 || die "go not found on PATH."

case "$MODE" in
  validate|plan|apply|destroy|show|import|regress|regress-destroy|negative|reorder|gone|statekeys) ;;
  *) die "unknown mode '$MODE'. Use one of: validate, plan, apply, destroy, show, import, regress, regress-destroy, negative, reorder, gone, statekeys" ;;
esac

# validate and plan for not-yet-created resources need no live credentials, so a
# placeholder keeps the provider's Configure step happy without implying access.
if [[ -z "${AUTHLETE_TOKEN:-}" ]]; then
  if [[ "$MODE" == "apply" || "$MODE" == "destroy" || "$MODE" == "import" || "$MODE" == "regress" || "$MODE" == "regress-destroy" ]]; then
    die "AUTHLETE_TOKEN is not set, and '$MODE' talks to the live API.
  Export an Organization Token first:
    export AUTHLETE_TOKEN='...'
  Service Access Tokens are scoped to one existing service and cannot create one."
  fi
  warn "AUTHLETE_TOKEN not set. Fine for '$MODE', which makes no API calls."
fi

# The provider reads AUTHLETE_TOKEN and AUTHLETE_SERVER_URL directly, so no
# TF_VAR plumbing is needed for credentials any more.
export AUTHLETE_TOKEN AUTHLETE_SERVER_URL

[[ -n "${AUTHLETE_NAME_PREFIX:-}" ]] && export TF_VAR_name_prefix="$AUTHLETE_NAME_PREFIX"
[[ -n "${AUTHLETE_ORGANIZATION_ID:-}" ]] && export TF_VAR_organization_id="$AUTHLETE_ORGANIZATION_ID"

# api_server_id for the import probe, which talks to the IdP directly.
case "${AUTHLETE_SERVER_URL:-https://us.authlete.com}" in
  *us.authlete.com) export TF_VAR_api_server_id_probe=76281 ;;
  *jp.authlete.com) export TF_VAR_api_server_id_probe=53285 ;;
  *eu.authlete.com) export TF_VAR_api_server_id_probe=63294 ;;
  *br.authlete.com) export TF_VAR_api_server_id_probe=47363 ;;
  *) export TF_VAR_api_server_id_probe="${AUTHLETE_API_SERVER_ID:-0}" ;;
esac

# api_server_id is no longer plumbed here: the provider derives it from the
# cluster URL and injects it. Set it on the resource for self-managed clusters.
[[ -n "${AUTHLETE_API_SERVER_ID:-}" ]] && warn "AUTHLETE_API_SERVER_ID is ignored; set api_server_id on the resource instead."

if [[ -z "${AUTHLETE_ORGANIZATION_ID:-}" ]]; then
  export TF_VAR_organization_id=0
  [[ "$MODE" == "apply" || "$MODE" == "destroy" ]] && die \
    "AUTHLETE_ORGANIZATION_ID is not set; the IdP create endpoint requires it."
fi

# ---------------------------------------------------------------------------
# Build the provider and point Terraform at the binary
# ---------------------------------------------------------------------------
say "Building provider from $REPO_ROOT"
mkdir -p "$BIN_DIR"
( cd "$REPO_ROOT" && go build -o "$BIN_DIR/terraform-provider-authlete" . )

# dev_overrides bypasses the registry entirely, so 'terraform init' is neither
# needed nor wanted -- with an override in place it errors on the unpublished
# provider. Terraform will print its own "Provider development overrides are in
# effect" warning on every command; that is expected here.
cat > "$TFRC" <<EOF
provider_installation {
  dev_overrides {
    "authlete/authlete" = "$BIN_DIR"
  }
  direct {}
}
EOF
export TF_CLI_CONFIG_FILE="$TFRC"

say "Provider: $BIN_DIR/terraform-provider-authlete"

# dev_overrides covers the Authlete provider, but main.tf also uses
# hashicorp/tls to generate a signing key, and that one does come from the
# registry. So init is needed after all -- on a fresh clone there is no
# .terraform directory and every command fails with "Missing required
# provider". The CLI warns about the override during init; that is expected.
#
# Each CLI gets its own data directory. Terraform and OpenTofu would otherwise
# share .terraform while populating it from different registries, and whichever
# ran last would leave the other unable to find hashicorp/tls -- including after
# a successful init, because the second init replaces the first one's providers.
export TF_DATA_DIR=".terraform-$(basename "$TF")"

# State is per-CLI too, and for a sharper reason than the plugin cache. Both
# CLIs record each resource's provider by its full registry address, so a state
# file written by one names registry.opentofu.org where the other expects
# registry.terraform.io. Handed the wrong one, Terraform tries to install
# authlete/authlete from OpenTofu's registry and fails with "authentication
# signature from unknown issuer", which says nothing about the real cause.
STATE="terraform-$(basename "$TF").tfstate"
STATE_ARGS=(-state="$STATE")

# The dependency lock file is the third thing the two CLIs cannot share, and
# unlike the data directory and the state file its location is fixed at the
# working directory root, so it has to be swapped rather than redirected. It
# records provider versions by full registry address, so a lock written by one
# CLI sends the other looking for registry.opentofu.org/hashicorp/tls in its own
# plugin cache and failing with "missing or corrupted provider plugins".
LOCK=".terraform.lock.hcl"
LOCK_MINE=".terraform.lock.$(basename "$TF").hcl"
if [[ -f "$LOCK_MINE" ]]; then
  cp "$LOCK_MINE" "$LOCK"
else
  rm -f "$LOCK"
fi
save_lock() { [[ -f "$LOCK" ]] && cp "$LOCK" "$LOCK_MINE"; }
trap save_lock EXIT
# Both conditions matter. A missing data directory is the first run for this
# CLI; a missing lock file means the swap above found none saved for it, which
# is the same situation even when the other CLI has left a data directory
# behind.
if [[ ! -d "$TF_DATA_DIR" || ! -f "$LOCK" ]]; then
  say "$TF init (first run in this checkout for $TF)"
  "$TF" init -input=false >/dev/null || die "$TF init failed"
  save_lock
fi

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
case "$MODE" in
  validate)
    say "$TF validate"
    "$TF" validate
    say "Provider loaded and configuration is valid."
    ;;
  plan)
    ensure_x25519_key
    STATE_ARGS+=(-var "x25519_pem_file=$X25519_PEM")
    say "$TF plan"
    "$TF" plan "${STATE_ARGS[@]}"
    ;;
  apply)
    ensure_x25519_key
    STATE_ARGS+=(-var "x25519_pem_file=$X25519_PEM")
    cat <<EOF

  This creates real objects in the Authlete organization the token belongs to:
    - one service, named "\${name_prefix}-service"
    - one client underneath it

  Run './run.sh destroy' afterwards to remove them.

EOF
    if [[ "${ASSUME_YES:-}" == "1" ]]; then
      say "$TF apply (ASSUME_YES=1)"
      "$TF" apply "${STATE_ARGS[@]}" -auto-approve
    else
      read -r -p "Continue? [y/N] " reply
      [[ "$reply" == "y" || "$reply" == "Y" ]] || die "aborted"
      say "$TF apply"
      "$TF" apply "${STATE_ARGS[@]}"
    fi
    say "Outputs"
    "$TF" output "${STATE_ARGS[@]}"
    ;;
  destroy)
    say "$TF destroy"
    if [[ "${ASSUME_YES:-}" == "1" ]]; then
      "$TF" destroy "${STATE_ARGS[@]}" -auto-approve
    else
      "$TF" destroy "${STATE_ARGS[@]}"
    fi
    ;;
  import)
    # Regression guard for the destructive-import bug. organization_id and
    # api_server_id are needed by the IdP but never returned by the cluster, so
    # when they were resource attributes the first plan after any import
    # proposed destroying the service and everything under it.
    #
    # The offline guard is internal/provider/import_safety_test.go; this is the
    # end-to-end version, because only a real import proves the whole path.
    say "Creating a throwaway service to import"
    SID=$(curl -fsS -X POST "${AUTHLETE_IDP_URL:-https://login.authlete.com}/api/service" \
      -H "Authorization: Bearer $AUTHLETE_TOKEN" -H "Content-Type: application/json" \
      -d "{\"apiServerId\":$TF_VAR_api_server_id_probe,\"organizationId\":$AUTHLETE_ORGANIZATION_ID,\"service\":{\"serviceName\":\"import-guard\",\"issuer\":\"https://import-guard.example.com\"}}" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["apiKey"])') || die "could not create the probe service"
    say "Created service $SID"

    workdir=$(mktemp -d)
    trap 'curl -fsS -o /dev/null -X POST "${AUTHLETE_IDP_URL:-https://login.authlete.com}/api/service/remove" -H "Authorization: Bearer $AUTHLETE_TOKEN" -H "Content-Type: application/json" -d "{\"apiServerId\":$TF_VAR_api_server_id_probe,\"organizationId\":$AUTHLETE_ORGANIZATION_ID,\"serviceId\":$SID}" 2>/dev/null; rm -rf "$workdir"' EXIT

    cat > "$workdir/main.tf" <<TF
terraform {
  required_providers { authlete = { source = "authlete/authlete" } }
}
provider "authlete" {
  organization_id = $AUTHLETE_ORGANIZATION_ID
}
resource "authlete_service" "imported" {
  service_name = "import-guard"
  issuer       = "https://import-guard.example.com"
}
TF
    ( cd "$workdir" && "$TF" import "${STATE_ARGS[@]}" authlete_service.imported "$SID" >/dev/null ) \
      || die "$TF import failed"
    say "Imported. Checking the plan is clean..."

    if ( cd "$workdir" && "$TF" plan "${STATE_ARGS[@]}" -detailed-exitcode -no-color >/dev/null 2>&1 ); then
      say "PASS: the plan after import is clean."
    else
      ( cd "$workdir" && "$TF" plan "${STATE_ARGS[@]}" -no-color 2>&1 | grep -E "must be replaced|forces replacement|^Plan:" | head -5 )
      die "FAIL: importing a service produced a non-empty plan.
  If it proposes replacement, the destructive-import bug is back -- check that
  x-speakeasy-terraform-ignore is still set on organizationId and apiServerId
  in .speakeasy/terraform_overlay.yaml."
    fi
    ;;
  regress)
    # Every fix in testing/regressions.tf shows up as a plan that is not empty
    # when it regresses, so the assertion is that the plan after an apply
    # proposes nothing. -detailed-exitcode returns 2 for "changes present",
    # which is the failure.
    cat <<EOF

  This creates real objects in the Authlete organization the token belongs to,
  one service named "\${name_prefix}-regressions" and a client under it,
  in testing/regressions/ with its own state.

  Run './run.sh regress-destroy' afterwards to remove them.

EOF
    if [[ "${ASSUME_YES:-}" != "1" ]]; then
      read -r -p "Continue? [y/N] " reply
      [[ "$reply" == "y" || "$reply" == "Y" ]] || die "aborted"
    fi

    workdir=$(mktemp -d)
    trap 'rm -rf "$workdir"' EXIT

    # Own directory and own state. The organization's service quota is small
    # and ../main.tf already uses a slot, so the two configurations cannot be
    # applied at the same time. Destroy one before running the other.
    cd "$TESTING_DIR/regressions"
    REG_STATE_ARGS=(-state="$TESTING_DIR/regressions/terraform-$(basename "$TF").tfstate")

    say "$TF apply (regressions/)"
    "$TF" apply "${REG_STATE_ARGS[@]}" -auto-approve

    say "$TF plan -detailed-exitcode (expecting no changes)"
    set +e
    "$TF" plan "${REG_STATE_ARGS[@]}" -detailed-exitcode -no-color > "$workdir/replan.txt" 2>&1
    rc=$?
    set -e

    case "$rc" in
      0)
        say "No changes proposed. Every fix in regressions.tf held."
        ;;
      2)
        cat "$workdir/replan.txt"
        die "A second plan proposed changes. One of the fixes has regressed.
  The attributes named above say which. regressions.tf documents what each
  one guards; the offline guards are scripts/patch-empty-lists.sh --check
  and scripts/fill-keep-order-stubs.py --check."
        ;;
      *)
        cat "$workdir/replan.txt"
        die "plan failed with exit $rc."
        ;;
    esac

    # check blocks report as warnings rather than failing the run, so they are
    # only noticed if something looks for them.
    if grep -q "Check block assertion failed" "$workdir/replan.txt"; then
      grep -A4 "Check block assertion failed" "$workdir/replan.txt"
      die "A check block failed. The plan was empty, so the value agrees with
  itself but is not the value that was written."
    fi
    say "All check block assertions passed."
    ;;
  negative)
    # Some fixes make something impossible. A clean plan cannot prove that; the
    # attempt being refused can, with the message that says why. Each directory
    # under negative/ holds a configuration that must fail and an `expect` file
    # holding a regular expression the failure has to match.
    #
    # Run in a copy, so no state lands in the repo. None of these reach the API:
    # two are refused at plan time by the schema or a validator, and the third
    # is refused in the transport before a request is sent.
    workdir=$(mktemp -d)
    trap 'rm -rf "$workdir"' EXIT

    failures=0
    for case_dir in "$TESTING_DIR"/negative/*/; do
      [[ -f "$case_dir/main.tf" ]] || continue
      name=$(basename "$case_dir")
      expect=$(cat "$case_dir/expect")
      case_mode=$(cat "$case_dir/mode" 2>/dev/null || echo plan)

      cp "$case_dir/main.tf" "$workdir/"
      out="$workdir/$name.txt"

      set +e
      if [[ "$name" == "no-token" ]]; then
        # The refusal fires in the transport, which only sees what was actually
        # sent, so it needs a request attempted. Nothing is created: the
        # transport refuses before the request leaves.
        ( cd "$workdir" && env -u AUTHLETE_TOKEN "$TF" "$case_mode" -auto-approve -no-color ) > "$out" 2>&1
      else
        ( cd "$workdir" && "$TF" "$case_mode" -no-color ) > "$out" 2>&1
      fi
      rc=$?
      set -e
      rm -f "$workdir/main.tf" "$workdir"/terraform.tfstate*

      if [[ $rc -eq 0 ]]; then
        warn "$name: succeeded, but it is supposed to fail."
        failures=$((failures + 1))
        continue
      fi
      if ! grep -qiE "$expect" "$out"; then
        warn "$name: failed, but not for the expected reason.
  Expected to match: $expect
  Got:"
        tail -12 "$out" >&2
        failures=$((failures + 1))
        continue
      fi
      say "$name: refused, with the expected message."
    done

    [[ $failures -eq 0 ]] || die "$failures negative case(s) did not behave as expected.
  Each one guards a fix that makes something impossible. See negative/README.md."
    say "Every negative case was refused for the right reason."
    ;;
  reorder)
    # Item 5: writing a list out of order on create always settled. Changing
    # the order of a list already in state did not: the list itself showed no
    # diff, but about 180 computed attributes went to "known after apply", the
    # apply sent nothing the server treated as a change, and the next plan
    # proposed the same thing again. Every import hit it, because imported
    # state holds Authlete's order.
    #
    # Two phases, because one configuration cannot express "then reorder it".
    cat <<EOF

  This creates one real service in the Authlete organization the token
  belongs to, and removes it again at the end.

EOF
    if [[ "${ASSUME_YES:-}" != "1" ]]; then
      read -r -p "Continue? [y/N] " reply
      [[ "$reply" == "y" || "$reply" == "Y" ]] || die "aborted"
    fi

    workdir=$(mktemp -d)
    trap 'say "Removing the probe resources"; if ( cd "$workdir" && "$TF" destroy -auto-approve -no-color >/dev/null 2>&1 ); then rm -rf "$workdir"; else warn "Cleanup failed; state retained at $workdir"; fi' EXIT

    # A genuine public key makes the import check exercise server-normalised
    # JWK JSON as well as list ordering. No private key is sent to a client.
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      -out "$workdir/private.pem" 2>/dev/null || die "could not generate the probe key"
    openssl pkey -in "$workdir/private.pem" -pubout \
      -out "$workdir/public.pem" 2>/dev/null || die "could not export the public probe key"

    write_reorder_config() {
      cat > "$workdir/main.tf" <<TF
terraform {
  required_providers { authlete = { source = "authlete/authlete" } }
}
provider "authlete" {
  organization_id = $AUTHLETE_ORGANIZATION_ID
}
resource "authlete_service" "s" {
  service_name = "${TF_VAR_name_prefix:-tftest}-reorder"
  issuer       = "https://reorder.example.com"

  supported_grant_types = [$1]
  supported_scopes = [$2]
  supported_introspection_auth_methods = [$4]
  supported_revocation_auth_methods = [$4]
  supported_backchannel_token_delivery_modes = [$6]
  fapi_modes = [$5]
}
resource "authlete_client" "c" {
  service_id = tostring(authlete_service.s.api_key)
  client_name = "${TF_VAR_name_prefix:-tftest}-reorder-client"
  client_type = "CONFIDENTIAL"
  fapi_modes = [$5]
  extension = {
    requestable_scopes_enabled = true
    requestable_scopes = [$3]
  }
  jwks = jsonencode({ keys = [jsondecode(provider::authlete::jwk_from_pem(
    file("$workdir/public.pem"), "public", "RS256", "sig"))] })
}
TF
    }

    A_GRANTS='"AUTHORIZATION_CODE", "REFRESH_TOKEN", "CLIENT_CREDENTIALS"'
    B_GRANTS='"CLIENT_CREDENTIALS", "AUTHORIZATION_CODE", "REFRESH_TOKEN"'
    A_SCOPES='{ name = "read" }, { name = "write" }, { name = "admin" }'
    B_SCOPES='{ name = "admin" }, { name = "write" }, { name = "read" }'
    A_REQUESTABLE='"write", "read"'
    B_REQUESTABLE='"read", "write"'
    A_AUTH='"CLIENT_SECRET_POST", "NONE"'
    B_AUTH='"NONE", "CLIENT_SECRET_POST"'
    # Message-signing modes may be combined. FAPI1 and FAPI2_SECURITY may not.
    A_FAPI='"FAPI2_MESSAGE_SIGNING_AUTH_RES", "FAPI2_MESSAGE_SIGNING_AUTH_REQ"'
    B_FAPI='"FAPI2_MESSAGE_SIGNING_AUTH_REQ", "FAPI2_MESSAGE_SIGNING_AUTH_RES"'
    A_DELIVERY='"PUSH", "POLL", "PING"'
    B_DELIVERY='"PING", "POLL", "PUSH"'

    write_reorder_config "$A_GRANTS" "$A_SCOPES" "$A_REQUESTABLE" "$A_AUTH" "$A_FAPI" "$A_DELIVERY"
    ( cd "$workdir" && "$TF" apply -auto-approve -no-color >/dev/null ) || die "apply failed"
    say "Applied with the lists in one order."

    if ! ( cd "$workdir" && "$TF" plan -detailed-exitcode -no-color >/dev/null 2>&1 ); then
      ( cd "$workdir" && "$TF" plan -no-color 2>&1 | grep -E "^Plan:" | head -1 )
      die "FAIL: the plan straight after the apply is not empty."
    fi
    say "The plan after the apply is clean."

    # The case that used to loop for ever: same values, different order.
    write_reorder_config "$B_GRANTS" "$B_SCOPES" "$B_REQUESTABLE" "$B_AUTH" "$B_FAPI" "$B_DELIVERY"
    if ( cd "$workdir" && "$TF" plan -detailed-exitcode -no-color >/dev/null 2>&1 ); then
      say "PASS: reordering a list already in state proposes nothing."
    else
      ( cd "$workdir" && "$TF" plan -no-color > "$workdir/p.txt" 2>&1 )
      grep -E "^Plan:" "$workdir/p.txt" | head -1
      printf '  attributes going unknown: %s\n' "$(grep -c 'known after apply' "$workdir/p.txt")" >&2
      die "FAIL: an order-only change plans a change, so it will never settle.
  The resource-level ModifyPlan in internal/provider/settled_plan.go restores
  prior state when every difference is an unknown. Check it is still wired:
  the framework finds it through ResourceWithModifyPlan."
    fi

    # Import has no saved configuration spelling, so Authlete's ordering and
    # JSON formatting enter state directly. The first plan must be clean too.
    IDS=$( cd "$workdir" && "$TF" show -json | python3 -c '
import json,sys
resources=json.load(sys.stdin)["values"]["root_module"]["resources"]
sid=next(r["values"]["api_key"] for r in resources if r["type"]=="authlete_service")
cid=next(r["values"]["client_id"] for r in resources if r["type"]=="authlete_client")
print(sid, cid)
' )
    read -r SID CID <<< "$IDS"
    CLIENT_IMPORT=$(python3 -c 'import json,sys; print(json.dumps({"service_id":sys.argv[1],"client_id":int(sys.argv[2])}))' "$SID" "$CID")
    cp "$workdir/terraform.tfstate" "$workdir/before-import.tfstate"
    if ! ( cd "$workdir" && "$TF" state rm authlete_client.c authlete_service.s >/dev/null \
      && "$TF" import -no-color authlete_service.s "$SID" >/dev/null \
      && "$TF" import -no-color authlete_client.c "$CLIENT_IMPORT" >/dev/null ); then
      # Restore our local test state so cleanup still owns both real objects.
      cp "$workdir/before-import.tfstate" "$workdir/terraform.tfstate"
      die "could not re-import the probe resources"
    fi
    if ( cd "$workdir" && "$TF" plan -detailed-exitcode -no-color >/dev/null 2>&1 ); then
      say "PASS: service and client import with reordered lists and a JWK Set plans no change."
    else
      ( cd "$workdir" && "$TF" plan -no-color > "$workdir/import-plan.txt" 2>&1 ) || true
      die "FAIL: import plans a change; see $workdir/import-plan.txt"
    fi
    ;;
  gone)
    # Items 1 and 2: deciding a resource is gone drops it from state and plans
    # a replacement, which creates a second service and orphans the original.
    # The generated code decided it from the status code, so any 404 -- an
    # nginx page, a proxy, a typo in server_url -- recreated everything. And a
    # cluster that never had the service answers exactly as one that deleted
    # it, so a wrong AUTHLETE_SERVER_URL did the same.
    #
    # Mocks stand in for both, so no second cluster is needed.
    cat <<EOF

  This creates one real service in the Authlete organization the token
  belongs to, and removes it again at the end. It also listens on
  127.0.0.1:8911 and 127.0.0.1:8912.

EOF
    if [[ "${ASSUME_YES:-}" != "1" ]]; then
      read -r -p "Continue? [y/N] " reply
      [[ "$reply" == "y" || "$reply" == "Y" ]] || die "aborted"
    fi

    command -v python3 >/dev/null || die "python3 is needed for the mock responses"

    workdir=$(mktemp -d)
    trap 'say "Removing the probe service"; ( cd "$workdir" && "$TF" destroy -auto-approve -no-color -var "server_url=$AUTHLETE_SERVER_URL" >/dev/null 2>&1 ); kill %1 %2 2>/dev/null; rm -rf "$workdir"' EXIT

    cat > "$workdir/mock.py" <<'PY'
import sys, http.server
port, status, body = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3].encode()
class H(http.server.BaseHTTPRequestHandler):
    def respond(self):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = do_DELETE = do_PUT = lambda s: s.respond()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
    python3 "$workdir/mock.py" 8911 404 '<html><title>404 Not Found</title><body>nginx</body></html>' &
    python3 "$workdir/mock.py" 8912 403 '{"resultCode":"A458203","resultMessage":"[A458203] Service not found: entity is null."}' &
    sleep 2

    cat > "$workdir/main.tf" <<TF
terraform {
  required_providers { authlete = { source = "authlete/authlete" } }
}
variable "server_url" { type = string }
provider "authlete" {
  organization_id = $AUTHLETE_ORGANIZATION_ID
  server_url      = var.server_url
}
resource "authlete_service" "s" {
  service_name = "${TF_VAR_name_prefix:-tftest}-gone"
  issuer       = "https://gone.example.com"
}
TF
    ( cd "$workdir" && "$TF" apply -auto-approve -no-color -var "server_url=$AUTHLETE_SERVER_URL" >/dev/null ) || die "apply failed"
    say "Applied. No refresh follows, deliberately."

    # The first version of this test ran "apply -refresh-only" here, because
    # the host was recorded on Read and a plan does not save state. That extra
    # step is exactly what hid the hole: a resource created and then looked
    # for on another host was unprotected, which is the report's own repro.
    # Create records the host now, so the guard has to hold from here with no
    # refresh in between. Reviewer found this; the harness had not.

    check_refuses() {
      local url=$1 what=$2
      if ( cd "$workdir" && "$TF" plan -no-color -var "server_url=$url" >/dev/null 2>&1 ); then
        ( cd "$workdir" && "$TF" plan -no-color -var "server_url=$url" 2>&1 | grep -E "^Plan:" | head -1 )
        die "FAIL: $what was treated as a deletion.
  Terraform would create a second service and leave the original running
  unmanaged. See internal/provider/missing_service.go."
      fi
      say "PASS: $what is refused rather than treated as a deletion."
    }

    check_refuses "http://127.0.0.1:8911" "a 404 with an unrelated body"
    check_refuses "http://127.0.0.1:8912" "a service missing from a different host"

    # And the behaviour that must survive: a service genuinely deleted, on the
    # host it was read from, still plans for recreation.
    SID=$( cd "$workdir" && "$TF" show -json | python3 -c 'import sys,json; print(json.load(sys.stdin)["values"]["root_module"]["resources"][0]["values"]["api_key"])' )
    curl -fsS -o /dev/null -X POST "${AUTHLETE_IDP_URL:-https://login.authlete.com}/api/service/remove" \
      -H "Authorization: Bearer $AUTHLETE_TOKEN" -H "Content-Type: application/json" \
      -d "{\"apiServerId\":$TF_VAR_api_server_id_probe,\"organizationId\":$AUTHLETE_ORGANIZATION_ID,\"serviceId\":$SID}" \
      || die "could not delete the service out of band"

    if ( cd "$workdir" && "$TF" plan -detailed-exitcode -no-color -var "server_url=$AUTHLETE_SERVER_URL" >/dev/null 2>&1 ); then
      die "FAIL: a service deleted out of band proposes no change, so it can never be recreated."
    fi
    say "PASS: a genuine deletion still plans for recreation."

    # And the Delete path, which refresh hides. The SDK drains a 404 body, so
    # the body-based check saw nothing there and a service already deleted in
    # the console made destroy fail. Only -refresh=false reaches it: with a
    # refresh, Read drops the resource first and Delete is never called.
    if ! ( cd "$workdir" && "$TF" destroy -refresh=false -auto-approve -no-color \
             -var "server_url=$AUTHLETE_SERVER_URL" >"$workdir/destroy.log" 2>&1 ); then
      sed -n '1,20p' "$workdir/destroy.log" >&2
      die "FAIL: destroy -refresh=false errors on a service that is already gone.
  The SDK calls utils.DrainBody on a 404, so serviceIsGone read an empty body.
  See internal/provider/captured_body.go."
    fi
    say "PASS: destroy -refresh=false succeeds on a service already deleted."
    ;;
  statekeys)
    # Items 3 and 7: the key checks used to run on every read of the value,
    # state included, because they lived on the custom type. Two consequences,
    # both of which break a plan rather than a configuration.
    #
    # A client registered through the API, or through DCR, may hold a key with
    # no kid, or a signing and an encryption key sharing one. Both are legal
    # per RFC 7517 and neither is something Terraform wrote.
    #
    # And v1.3.17 stored jwks = "" for every client, which the state upgrader
    # copies as written, so the malformed-document check rejected it.
    #
    # Nothing here is in the configuration, so a validator must never see it.
    cat <<EOF

  This creates one real service and two clients in the Authlete organization
  the token belongs to, and removes them again at the end.

EOF
    if [[ "${ASSUME_YES:-}" != "1" ]]; then
      read -r -p "Continue? [y/N] " reply
      [[ "$reply" == "y" || "$reply" == "Y" ]] || die "aborted"
    fi

    workdir=$(mktemp -d)
    trap 'say "Removing the probe service"; ( cd "$workdir" && "$TF" destroy -auto-approve -no-color >/dev/null 2>&1 ); rm -rf "$workdir"' EXIT

    cat > "$workdir/main.tf" <<TF
terraform {
  required_providers { authlete = { source = "authlete/authlete" } }
}
provider "authlete" {
  organization_id = $AUTHLETE_ORGANIZATION_ID
}
resource "authlete_service" "s" {
  service_name = "${TF_VAR_name_prefix:-tftest}-statekeys"
  issuer       = "https://statekeys.example.com"
}
TF
    ( cd "$workdir" && "$TF" apply -auto-approve -no-color >/dev/null ) || die "apply failed"
    SID=$( cd "$workdir" && "$TF" show -json | python3 -c 'import sys,json; print(json.load(sys.stdin)["values"]["root_module"]["resources"][0]["values"]["api_key"])' )

    # The clients are made through the API, because the provider refuses to
    # write these shapes and that refusal is correct: the point is that it
    # must still read them back.
    python3 - "$SID" <<'PY' > "$workdir/clients.json"
import json, os, sys, urllib.request

# A static public key. Authlete stores a client's key set without checking
# that the modulus is a real one, and this test is about the shape of the
# document, not the mathematics, so there is no dependency on a crypto
# library here.
def pub():
    return {"kty": "RSA", "n": "sXchDaQ" + "A" * 335, "e": "AQAB"}

sid = sys.argv[1]
base = os.environ["AUTHLETE_SERVER_URL"]
tok = os.environ["AUTHLETE_TOKEN"]
cases = {
    "no-kid": {"keys": [dict(pub(), alg="RS256", use="sig")]},
    "shared-kid": {"keys": [dict(pub(), kid="k", alg="RS256", use="sig"),
                            dict(pub(), kid="k", alg="RSA-OAEP-256", use="enc")]},
}
out = {}
for name, jwks in cases.items():
    body = json.dumps({"clientName": "statekeys-" + name, "jwks": json.dumps(jwks)}).encode()
    req = urllib.request.Request(f"{base}/api/{sid}/client/create", data=body,
                                 headers={"Authorization": "Bearer " + tok,
                                          "Content-Type": "application/json"})
    out[name] = json.load(urllib.request.urlopen(req))["clientId"]
print(json.dumps(out))
PY
    A=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["no-kid"])' "$workdir/clients.json")
    B=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["shared-kid"])' "$workdir/clients.json")
    say "Created a client with a kid-less key and one with two keys sharing a kid."

    cat >> "$workdir/main.tf" <<TF

import {
  to = authlete_client.no_kid
  id = jsonencode({ client_id = $A, service_id = "$SID" })
}
import {
  to = authlete_client.shared_kid
  id = jsonencode({ client_id = $B, service_id = "$SID" })
}
resource "authlete_client" "no_kid" {
  service_id  = "$SID"
  client_name = "statekeys-no-kid"
}
resource "authlete_client" "shared_kid" {
  service_id  = "$SID"
  client_name = "statekeys-shared-kid"
}
TF
    if ! ( cd "$workdir" && "$TF" apply -auto-approve -no-color >/dev/null 2>&1 ); then
      ( cd "$workdir" && "$TF" apply -auto-approve -no-color 2>&1 | grep -E "^Error" | head -3 )
      die "FAIL: a client whose server-side keys are legal could not be imported.
  These checks belong on an attribute validator, which sees configuration
  only. On the custom type they run on every read, state included."
    fi
    if ! ( cd "$workdir" && "$TF" plan -detailed-exitcode -no-color >/dev/null 2>&1 ); then
      ( cd "$workdir" && "$TF" plan -no-color 2>&1 | grep -E "^Error|^Plan:" | head -3 )
      die "FAIL: an imported client does not plan cleanly."
    fi
    say "PASS: both import and plan cleanly."

    # What a v1.3.17 upgrade leaves behind, which the upgrader copies as written.
    python3 - "$workdir/terraform.tfstate" <<'PY'
import json, sys
p = sys.argv[1]
s = json.load(open(p))
for r in s["resources"]:
    if r["type"] == "authlete_client":
        for i in r["instances"]:
            i["attributes"]["jwks"] = ""
s["serial"] = s.get("serial", 1) + 1
json.dump(s, open(p, "w"), indent=2)
PY
    if ( cd "$workdir" && "$TF" plan -no-color >/dev/null 2>&1 ); then
      say 'PASS: a client carrying jwks = "" from a 1.3.17 upgrade still plans.'
    else
      ( cd "$workdir" && "$TF" plan -no-color 2>&1 | grep -E "^Error" | head -2 )
      die 'FAIL: jwks = "" breaks the plan, so every client upgraded from
  v1.3.17 is stuck. v1.3.17 set it for all of them: see _ = d.Set("jwks", nil)
  in its client.go.'
    fi
    ;;
  regress-destroy)
    cd "$TESTING_DIR/regressions"
    say "$TF destroy (regressions/)"
    "$TF" destroy -state="$TESTING_DIR/regressions/terraform-$(basename "$TF").tfstate" \
      ${ASSUME_YES:+-auto-approve}
    ;;
  show)
    say "$TF show"
    # show takes the state file as a positional argument, not -state.
    "$TF" show "$STATE"
    ;;
esac
