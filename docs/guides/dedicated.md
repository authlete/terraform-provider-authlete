---
# Authlete Terraform provider
page_title: "Configuring Authlete on Dedicated Cloud"
subcategory: ""
description: |-
  
---

# Authlete dedicated cloud server

This provider supports configuring different deployment services: regional deployment, dedicated cloud, and on-premise deployments.

The API server to use is selected by setting the property `api_server` of the provider, or using the environment variable `AUTHLETE_API_SERVER`.

The default value of the API server is `https://api.authlete.com`, which is the shared server.

## Configuring using provider property

If you configure the server using `api_server` the provider section will be similiar to example below:

```hcl
provider "authlete" {
    api_server = "https://api.authlete-server.mydomain.com"
}
```

Another option is to use terraform variables like below:

```hcl
variable authlete_api_server {
    description="The authlete api server"
    default = "https://api.authlete-server.mydomain.com"
}

provider "authlete" {
    api_server = var.authlete_api_server
}
```

## Regional shared cloud servers

If you are a tenant of one of Authlete's regional shared servers, please get in touch with Authlete on how to configure this parameter properly.
