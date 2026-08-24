#!/usr/bin/env bash
#
# Exercise the locally built terraform-provider-authlete without publishing it.
#
#   ./run.sh validate    # provider loads, config and schema are consistent (no API calls, no token)
#   ./run.sh plan        # default; shows what would be created (no API calls for new resources)
#   ./run.sh apply       # CREATES A REAL SERVICE AND CLIENT in your Authlete org
#   ./run.sh destroy     # deletes what apply created
#   ./run.sh show        # print current state
#
# Terraform finds the provider through a dev_overrides block written to a
# throwaway CLI config in this directory. Your ~/.terraformrc is never touched.
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

REPO_ROOT="$(cd .. && pwd)"
BIN_DIR="$PWD/.provider-bin"
TFRC="$PWD/.terraformrc.dev"
MODE="${1:-plan}"

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
command -v terraform >/dev/null 2>&1 || die \
  "terraform not found on PATH. Install it with: brew install hashicorp/tap/terraform
  (This is the same dependency that makes 'go generate' fail during generation.)"
command -v go >/dev/null 2>&1 || die "go not found on PATH."

case "$MODE" in
  validate|plan|apply|destroy|show) ;;
  *) die "unknown mode '$MODE'. Use one of: validate, plan, apply, destroy, show" ;;
esac

# validate and plan for not-yet-created resources need no live credentials, so a
# placeholder keeps the provider's Configure step happy without implying access.
if [[ -z "${AUTHLETE_TOKEN:-}" ]]; then
  if [[ "$MODE" == "apply" || "$MODE" == "destroy" ]]; then
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
    "speakeasy/authlete" = "$BIN_DIR"
  }
  direct {}
}
EOF
export TF_CLI_CONFIG_FILE="$TFRC"

say "Provider: $BIN_DIR/terraform-provider-authlete"

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
case "$MODE" in
  validate)
    say "terraform validate"
    terraform validate
    say "Provider loaded and configuration is valid."
    ;;
  plan)
    say "terraform plan"
    terraform plan
    ;;
  apply)
    cat <<EOF

  This creates real objects in the Authlete organization the token belongs to:
    - one service, named "\${name_prefix}-service"
    - one client underneath it

  Run './run.sh destroy' afterwards to remove them.

EOF
    if [[ "${ASSUME_YES:-}" == "1" ]]; then
      say "terraform apply (ASSUME_YES=1)"
      terraform apply -auto-approve
    else
      read -r -p "Continue? [y/N] " reply
      [[ "$reply" == "y" || "$reply" == "Y" ]] || die "aborted"
      say "terraform apply"
      terraform apply
    fi
    say "Outputs"
    terraform output
    ;;
  destroy)
    say "terraform destroy"
    if [[ "${ASSUME_YES:-}" == "1" ]]; then
      terraform destroy -auto-approve
    else
      terraform destroy
    fi
    ;;
  show)
    say "terraform show"
    terraform show
    ;;
esac
