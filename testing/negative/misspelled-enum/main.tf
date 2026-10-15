# Issue 10: misspelled enum values reached Authlete unchecked.
#
# A typo used to travel to the API and come back as an opaque error, or worse
# be accepted and change nothing. A plan validator now checks list values
# against the enum types the SDK generates from the spec, so the permitted set
# cannot drift from the API.
#
# The message has to name the attribute and the bad value, otherwise a service
# with two hundred attributes gives no clue where to look.
terraform {
  required_providers {
    authlete = { source = "authlete/authlete" }
  }
}

provider "authlete" {
  organization_id = 1
}

resource "authlete_service" "bad_enum" {
  service_name = "negative-enum"

  # AUTHORIZATION_CODE, with one letter too many.
  supported_grant_types = ["AUTHORIZATION_CODEE"]
}
