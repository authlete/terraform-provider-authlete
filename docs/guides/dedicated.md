---
# Authlete Terraform provider
page_title: "Authlete Terraform provider"
subcategory: ""
description: |-
  
---

# Authlete dedicated server

This provider does support configuring different deployment services, like regional deployment, dedicated cloud or on-premise deployments using the property `api_server` of the provider.

## configuring the provider

```hcl
terraform {
  required_providers {
    authlete = {
      source = "authelte/terraform-provider"
      version = ">= 1.0"
    }
  }
}

provider "authlete" {
    api_server = var.authlete_server
	service_owner_key = var.authlete_api_key
	service_owner_secret = var.authlete_api_secret
}
```

the `api_server` can be also configured using `AUTHLETE_API_SERVER` environment variable.

The default value of this parameter is `https://api.authlete.com`

## Region datacenter

If your tenant is running on your Authlete specific datacenter, please get in touch with Authlete to configure this parameter properly.

