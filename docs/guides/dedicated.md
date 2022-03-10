---
# Authlete Terraform provider
page_title: "Configuring Authlete on Dedicated Cloud"
subcategory: ""
description: |-
  
---

# Authlete dedicated cloud

This provider does support configuring different deployment services: regional deployment, dedicated cloud or on-premise deployments.

This can be accomplished by defining the property `api_server` of the provider, or using the environment variable `AUTHLETE_API_SERVER`.

The default value of the api server is `https://api.authlete.com`. which is your share

## configuring using provider property

if you will configure the server using `api_server` the provider section will be similiar to example below.

```hcl

provider "authlete" {
    api_server = "https://api.authlete-server.mydomain.com"
}
```

on other option is to use terraform variables like below

```hcl

variable authlete_api_server {
    description="The authlete api server"
    default = "https://api.authlete-server.mydomain.com"
}

provider "authlete" {
    api_server = var.authlete_api_server
}
```


## Region datacenter

If your tenant is on regional datacenter, please get in touch with Authlete to configure this parameter properly.

