---
# Authlete Terraform provider
page_title: "Authlete Terraform provider"
subcategory: ""
description: |-
  
---

# Authlete Terraform provider

This Terraform provider allow you to configure services on Authlete, the FAPI as a service platform.

This provider support every parameter available on service owner console of Authlete, allowing you to create and maintain 
the configuration affecting you Authorization server under version control.

## First step

[Sign up for free on Authlete portal](https://so.authlete.com/accounts/signup) and take note of your API Key and Secret under [your profile page](https://so.authlete.com/profile?locale=en).



## installing the provider 

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
	service_owner_key = var.authlete_api_key
	service_owner_secret = var.authlete_api_secret
}
```

Then, initialize your Terraform workspace by running `terraform init`.

The `service_owner_key` and `service_owner_secret` are required by the provider in order to create and change the services for you.

As they are sensitive parameters we suggest to use environment variables, variables using command line or local variable file. 
The environment variables are `AUTHLETE_SO_KEY` and `AUTHLETE_SO_SECRET` or populate it using a secret management provider, like [Vault provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs).



