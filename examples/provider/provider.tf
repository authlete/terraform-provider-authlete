terraform {
  required_providers {
    authlete = {
      source  = "authlete/authlete"
      version = "0.0.1"
    }
  }
}

provider "authlete" {
  # An Organization Token from the Authlete console. Creating a service requires
  # one; a Service Access Token is scoped to a single existing service and
  # cannot create another.
  #
  # Prefer the environment variable. A token written here ends up in version
  # control.
  # bearer = "..." # or set AUTHLETE_TOKEN

  # Your regional cluster. Defaults to https://us.authlete.com.
  server_url = "https://us.authlete.com" # or set AUTHLETE_SERVER_URL

  # Dedicated Cloud and On-Premise deployments only. Shared Cloud uses
  # Authlete's own IdP and needs nothing here.
  # idp_host = "authlete-login.example.com" # or set AUTHLETE_IDP_HOST

  # For a self-managed deployment behind a proxy or a private CA.
  # http_headers    = { "X-Example" = "value" }
  # tls_skip_verify = false
}
