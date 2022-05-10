---
# Authlete Terraform provider
page_title: "Authlete Terraform provider"
subcategory: ""
description: |-
  
---

# Authlete Terraform provider

This Terraform provider allow you to configure services on Authlete, the OAuth 2, OpenID Connect, Financial API (FAPI), and Open Banking authorization-as-a-service platform.

This provider support every parameter available on service owner console of Authlete, allowing you to create and maintain the configuration of your authorization server under version control.

## First step

[Sign up for a free Authlete trial account](https://so.authlete.com/accounts/signup) if you do not already have one, and take note of your API Key and Secret under [your profile page](https://so.authlete.com/profile?locale=en).


## Installing the provider

In your `main.tf` file, include the snippet below:

```hcl
terraform {
  required_providers {
    authlete = {
      source = "authlete/terraform-provider"
      version = ">= 0.3"
    }
  }
}

provider "authlete" {
}
```

and initialize your project by running `terraform init`.

## Configuring the provider

The provider can be configured using attributes or environment variables, with attributes taking precedence. The service owner key and secret can be retrieved from your [profile page under service owner console](https://so.authlete.com/services?locale=en).

Below is a table with the attributes and respective environment variables.

| attribute            | environment variable | required | default value            |
|----------------------|----------------------|----------|--------------------------|
| service_owner_key    | AUTHLETE_SO_KEY      | true     |                          |
| service_owner_secret | AUTHLETE_SO_SECRET   | true     |                          |
| api_server           | AUTHLETE_API_SERVER  |          | https://api.authlete.com |


As they are sensitive parameters we suggest to never hardcode it on terraform files. Use environment variables, variables using command line, or local variable file instead.

Another option is to populate the values using a secret management provider, like [Vault provider](https://registry.terraform.io/providers/hashicorp/vault/latest/docs).

Checkout the [Hello World sample](https://github.com/authlete/authlete-terraform-samples/tree/main/helloworld) for a gentle intro on configuring the provider.

## Bootstrapping Terraform state from Authlete config

See [Import guide](guides/import).

