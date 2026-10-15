---
page_title: "Shared Cloud, Dedicated Cloud and On-Premise"
subcategory: ""
description: |-
  Which settings each kind of Authlete deployment needs, and why creating a
  service talks to a different host than everything else.
---

# Shared Cloud, Dedicated Cloud and On-Premise

Most of what this provider does talks to your Authlete cluster. Creating and
deleting a service does not: those two operations go through Authlete's identity
server. That split is why some deployments need settings others can ignore.

## What goes where

| Operation | Host |
|---|---|
| Create a service | the identity server |
| Delete a service | the identity server |
| Everything else | your cluster, the `server_url` |

On Shared Cloud the identity server is `login.authlete.com` and the provider
finds it on its own. On a deployment you run yourself it is your own host, and
the provider has no way to guess it.

## Shared Cloud

Set two things.

```terraform
provider "authlete" {
  # bearer = "..." # prefer AUTHLETE_TOKEN
  server_url      = "https://us.authlete.com"
  organization_id = 123456
}
```

`api_server_id` is derived from `server_url` for the four public clusters, so
you do not set it. `idp_host` is left unset, which routes service create and
delete to `login.authlete.com`.

The public clusters are `us`, `jp`, `eu` and `br`, each `*.authlete.com`.

## Dedicated Cloud and On-Premise

Set four things. None of the last three can be derived, because your hosts and
identifiers are yours.

```terraform
provider "authlete" {
  # bearer = "..." # prefer AUTHLETE_TOKEN
  server_url      = "https://api.authlete.example.com"
  idp_host        = "login.authlete.example.com"
  api_server_id   = 12345
  organization_id = 123456
}
```

`api_server_id` is the cluster ID, shown in the Authlete console. `idp_host` is
your own identity server.

Each also reads an environment variable: `AUTHLETE_SERVER_URL`,
`AUTHLETE_IDP_HOST`, `AUTHLETE_API_SERVER_ID` and `AUTHLETE_ORGANIZATION_ID`.

### If you leave `idp_host` unset

The provider refuses rather than falling back. When `server_url` is not one of
the four public clusters, service create and delete stop with an error naming
the host it would otherwise have used.

That refusal is deliberate. The alternative is sending your organization token
to Authlete's shared identity server, which is a credential leaving your
deployment without anyone asking for it.

### If you leave `api_server_id` unset

The identity server rejects create and delete with an `apiServerId` error. The
provider cannot supply it, because the built-in table covers only the four
public clusters.

## Proxies and private certificate authorities

Two more settings exist for self-managed deployments:

```terraform
provider "authlete" {
  http_headers    = { "X-Example" = "value" }
  tls_skip_verify = false
}
```

`tls_skip_verify` disables certificate verification. Use it only against a
deployment you control, never against a shared cluster.

## Which token

An **Organization Token**, on every deployment type. A Service Access Token is
scoped to one existing service and cannot create another, so an apply fails on
the first service it reaches. The provider says so rather than returning a bare
401.
