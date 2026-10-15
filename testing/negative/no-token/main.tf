# Issue 20: no token configured failed once per resource with a bare 401.
#
# Terraform asks the provider to configure itself once and then plans every
# resource, so a missing token produced one opaque 401 per resource, none of
# which said the token was missing. The provider now refuses during Configure,
# before anything is sent, and says what is missing.
#
# run.sh clears AUTHLETE_TOKEN for this case only.
terraform {
  required_providers {
    authlete = { source = "authlete/authlete" }
  }
}

provider "authlete" {
  organization_id = 1
}

resource "authlete_service" "no_token" {
  service_name = "negative-no-token"
}
