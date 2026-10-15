#!/usr/bin/env bash
#
# Exercise the locally built terraform-provider-authlete without publishing it.
#
#   ./run.sh validate    # provider loads, config and schema are consistent (no API calls, no token)
#   ./run.sh plan        # default; shows what would be created (no API calls for new resources)
#   ./run.sh apply       # CREATES A REAL SERVICE AND CLIENT in your Authlete org
#   ./run.sh destroy     # deletes what apply created
#   ./run.sh import      # create a service, import it, and assert the plan is clean
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
  validate|plan|apply|destroy|show|import|regress|regress-destroy|negative) ;;
  *) die "unknown mode '$MODE'. Use one of: validate, plan, apply, destroy, show, import, regress, regress-destroy, negative" ;;
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
    say "$TF plan"
    "$TF" plan "${STATE_ARGS[@]}"
    ;;
  apply)
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
