# ---------------------------------------------------------------------------
# Regression configuration.
#
# Self-contained, with its own state, because the organization's service quota
# is small and the baseline config in ../main.tf already uses a slot. Run it
# with ../run.sh regress, which applies this and then asserts the second plan
# proposes nothing.
#
# Every resource here exists to catch one bug that was fixed, by making the bug
# visible as a plan that is not empty.
#
# The `check` blocks assert the things a clean plan cannot: that a value came
# back in the shape it was written, rather than merely agreeing with itself.
#
# Scope ordering has its own multi-phase test in ../run.sh reorder. That
# checks supported_scopes and extension.requestable_scopes after creation,
# an order-only edit and import, rather than only after this initial apply.
# ---------------------------------------------------------------------------

terraform {
  required_providers {
    authlete = {
      source = "authlete/authlete"
    }
  }
}

variable "organization_id" {
  description = "Authlete organization services are created under."
  type        = number
}

variable "name_prefix" {
  description = "Prefix for created object names, so test artifacts are identifiable."
  type        = string
  default     = "tftest"
}

provider "authlete" {
  organization_id = var.organization_id
}

resource "authlete_service" "regressions" {
  service_name = "${var.name_prefix}-regressions"
  issuer       = "https://${var.name_prefix}-regressions.example.com"
  description  = "Regression cases. Safe to delete."

  # -------------------------------------------------------------------------
  # Issue 1: an explicitly empty list must stay empty.
  #
  # The provider read an absent list as null. Writing `= []` therefore applied
  # once and then proposed `[] -> null` on every subsequent plan, forever. The
  # fix reads an absent list as an empty list at 14 sites; the offline guard is
  # scripts/patch-empty-lists.sh --check and internal/provider/nullable_arrays_test.go.
  #
  # These three are patched sites. If the patch is lost, each one reappears as
  # a proposed change on the second plan.
  # -------------------------------------------------------------------------
  supported_displays      = []
  supported_prompt_values = []
  supported_claim_types   = []

  # -------------------------------------------------------------------------
  # Issue 12: list order must survive a round trip.
  #
  # Authlete returns these in an order of its own choosing, which is not the
  # order they were sent in. Terraform compares lists element by element, so a
  # reordered response reads as an edit and every plan proposed rewriting the
  # list. The fix is a KeepOrder plan modifier per list, which holds the state
  # value when the two differ only by order.
  #
  # Each list below is written in an order chosen to differ from both
  # alphabetical and the order Authlete returns. If a modifier is dropped, that
  # list shows up as a proposed change.
  # -------------------------------------------------------------------------
  supported_grant_types = [
    "REFRESH_TOKEN",
    "CLIENT_CREDENTIALS",
    "AUTHORIZATION_CODE",
  ]

  supported_response_types = [
    "ID_TOKEN",
    "CODE",
    "NONE",
  ]

  supported_token_auth_methods = [
    "PRIVATE_KEY_JWT",
    "CLIENT_SECRET_BASIC",
    "TLS_CLIENT_AUTH",
    "NONE",
  ]

  supported_service_profiles = [
    "OPEN_BANKING",
    "FAPI",
  ]

  supported_attachments = [
    "EXTERNAL",
    "EMBEDDED",
  ]

  # Not a reordering case. Authlete refuses supported_attachments containing
  # EXTERNAL unless this contains sha-256 (A039238), so it is here to make the
  # case above legal.
  supported_digest_algorithms = ["sha-256"]

  supported_claims = [
    "sub",
    "email",
    "name",
    "address",
  ]

  # -------------------------------------------------------------------------
  # Identifiers and secrets must not plan as unknown.
  #
  # api_key and api_secret are assigned by Authlete and never change once
  # assigned. When they planned as "(known after apply)", every unrelated edit
  # showed them as changing, and anything referring to them went unknown too,
  # which cascaded into the client below.
  #
  # access_token_duration is here only to give a later edit something harmless
  # to change, so the cascade is visible if it returns.
  # -------------------------------------------------------------------------
  access_token_duration = 3600
}

# ---------------------------------------------------------------------------
# A client under the regression service.
# ---------------------------------------------------------------------------
resource "authlete_client" "regressions" {
  service_id = tostring(authlete_service.regressions.api_key)

  client_name   = "${var.name_prefix}-regressions-client"
  client_type   = "CONFIDENTIAL"
  redirect_uris = ["https://${var.name_prefix}-regressions.example.com/callback"]

  # Issue 12 again, on the three client lists that reorder.
  grant_types = [
    "REFRESH_TOKEN",
    "AUTHORIZATION_CODE",
  ]

  response_types = [
    "ID_TOKEN",
    "CODE",
  ]

  response_modes = [
    "FORM_POST",
    "QUERY",
  ]

  # -------------------------------------------------------------------------
  # Mutually exclusive certificate subject types.
  #
  # Authlete accepts exactly one of tls_client_auth_subject_dn and the four
  # tls_client_auth_san_* attributes, and silently clears the others when one
  # is set. Terraform then saw the cleared attribute as drift it should restore,
  # and fought the server on every plan. A plan modifier clears the superseded
  # ones locally so state matches what the server actually holds.
  #
  # Only one is set here. To exercise the switch by hand, move the value to
  # tls_client_auth_san_dns and apply: the plan should show subject_dn clearing
  # and nothing else, and the plan after that should be empty.
  # -------------------------------------------------------------------------
  token_auth_method          = "TLS_CLIENT_AUTH"
  tls_client_auth_subject_dn = "CN=regressions,OU=test,O=Authlete"
}

# ---------------------------------------------------------------------------
# Assertions that a clean plan alone does not make.
#
# A plan being empty proves a value agrees with itself. These check that the
# value is also the one that was written.
#
# check blocks need Terraform 1.5 or later. They report failures as warnings
# rather than failing the run, so run.sh greps for them.
# ---------------------------------------------------------------------------

check "empty_lists_stayed_empty" {
  assert {
    condition = alltrue([
      authlete_service.regressions.supported_displays != null,
      authlete_service.regressions.supported_prompt_values != null,
      authlete_service.regressions.supported_claim_types != null,
    ])
    error_message = join(" ", [
      "An explicitly empty list read back as null, which is issue 1 returning.",
      "An absent list must read as [] so that `= []` is stable.",
      "Check scripts/patch-empty-lists.sh --check.",
    ])
  }

  assert {
    condition = alltrue([
      length(authlete_service.regressions.supported_displays) == 0,
      length(authlete_service.regressions.supported_prompt_values) == 0,
      length(authlete_service.regressions.supported_claim_types) == 0,
    ])
    error_message = "A list written as [] came back with elements in it."
  }
}

check "list_order_was_preserved" {
  assert {
    condition = authlete_service.regressions.supported_grant_types == tolist([
      "REFRESH_TOKEN", "CLIENT_CREDENTIALS", "AUTHORIZATION_CODE",
    ])
    error_message = join(" ", [
      "supported_grant_types came back in a different order, which is issue 12",
      "returning. The KeepOrder plan modifier for this list is missing or not wired.",
      "Check scripts/fill-keep-order-stubs.py --check.",
    ])
  }

  assert {
    condition = authlete_service.regressions.supported_response_types == tolist([
      "ID_TOKEN", "CODE", "NONE",
    ])
    error_message = "supported_response_types was reordered. See issue 12."
  }

  assert {
    condition = authlete_client.regressions.grant_types == tolist([
      "REFRESH_TOKEN", "AUTHORIZATION_CODE",
    ])
    error_message = "Client grant_types was reordered. See issue 12."
  }

  assert {
    condition = authlete_client.regressions.response_modes == tolist([
      "FORM_POST", "QUERY",
    ])
    error_message = "Client response_modes was reordered. See issue 12."
  }
}

check "identifiers_are_known" {
  assert {
    condition     = authlete_service.regressions.api_key != null && authlete_service.regressions.api_key != 0
    error_message = "The service api_key is absent from state. It should be assigned on create and stable thereafter."
  }

  assert {
    condition     = authlete_client.regressions.client_id != null && authlete_client.regressions.client_id != 0
    error_message = "The client client_id is absent from state."
  }
}

check "superseded_subject_types_are_clear" {
  assert {
    condition = alltrue([
      authlete_client.regressions.tls_client_auth_san_dns == null || authlete_client.regressions.tls_client_auth_san_dns == "",
      authlete_client.regressions.tls_client_auth_san_email == null || authlete_client.regressions.tls_client_auth_san_email == "",
      authlete_client.regressions.tls_client_auth_san_ip == null || authlete_client.regressions.tls_client_auth_san_ip == "",
      authlete_client.regressions.tls_client_auth_san_uri == null || authlete_client.regressions.tls_client_auth_san_uri == "",
    ])
    error_message = join(" ", [
      "A tls_client_auth_san_* attribute holds a value while subject_dn is set.",
      "Authlete accepts exactly one, so the others must read as cleared.",
    ])
  }

  assert {
    condition     = authlete_client.regressions.tls_client_auth_subject_dn == "CN=regressions,OU=test,O=Authlete"
    error_message = "tls_client_auth_subject_dn did not round trip."
  }
}

output "regressions_service_api_key" {
  description = "Service ID of the regression service."
  value       = authlete_service.regressions.api_key
}
