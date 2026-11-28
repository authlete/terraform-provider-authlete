terraform {
  required_providers {
    authlete = {
      source  = "authlete/authlete"
      version = "3.1.2"
    }
  }
}

provider "authlete" {
  server_url = "..." # Optional - can use AUTHLETE_SERVER_URL environment variable
}