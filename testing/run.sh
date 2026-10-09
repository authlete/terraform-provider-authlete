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
  validate|plan|apply|destroy|show|import) ;;
  *) die "unknown mode '$MODE'. Use one of: validate, plan, apply, destroy, show" ;;
esac

# validate and plan for not-yet-created resources need no live credentials, so a
# placeholder keeps the provider's Configure step happy without implying access.
if [[ -z "${AUTHLETE_TOKEN:-}" ]]; then
  if [[ "$MODE" == "apply" || "$MODE" == "destroy" || "$MODE" == "import" ]]; then
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
  show)
    say "$TF show"
    # show takes the state file as a positional argument, not -state.
    "$TF" show "$STATE"
    ;;
esac
