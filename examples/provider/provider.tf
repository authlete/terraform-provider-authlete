terraform {
  required_providers {
    authlete = {
      source  = "speakeasy/authlete"
      version = "0.0.1"
    }
  }
}

provider "authlete" {
  server_url = "..." # Optional - can use AUTHLETE_SERVER_URL environment variable
}