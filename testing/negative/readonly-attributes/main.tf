# Issues 6 and 7: settings the server ignores, or owns.
#
# hsks, sns_credentials and metadata were accepted in configuration and then
# discarded by Authlete, and metadata diffed forever after an import because
# the server rewrites it. All three are readOnly in the overlay now, so they
# leave the request model entirely and Terraform refuses them in configuration
# rather than silently dropping them.
#
# They remain readable. The positive half of this is in regressions.tf.
terraform {
  required_providers {
    authlete = { source = "authlete/authlete" }
  }
}

provider "authlete" {
  organization_id = 1
}

resource "authlete_service" "readonly" {
  service_name = "negative-readonly"

  metadata = [
    { key = "clientCount", value = "1" },
  ]
}
