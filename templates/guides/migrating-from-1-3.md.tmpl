---
page_title: "Migrating from 1.3.x"
subcategory: ""
description: |-
  What changed between the 1.3.x provider and 3.0, and what to do about each.
---

# Migrating from 1.3.x

The 3.0 provider is generated from Authlete's OpenAPI description rather than
written by hand, so attribute names follow the API. Most of your configuration
carries over by renaming. This guide covers the changes that need a decision
from you rather than a rename.

Read it before upgrading. Two of these change where your private keys live.

## Authentication

1.3.x authenticated with a key and secret pair:

```terraform
provider "authlete" {
  service_owner_key    = "..."
  service_owner_secret = "..."
}
```

3.0 uses a token:

```terraform
provider "authlete" {
  organization_id = 123456
}
```

The token comes from `AUTHLETE_TOKEN`, or from `bearer` in the provider block.
`AUTHLETE_SERVER_URL` and `AUTHLETE_ORGANIZATION_ID` cover the other two.

`api_secret` is gone from the service resource. Authlete 3.0 never returns one,
so the attribute could only ever resolve to null. If your configuration reads
`authlete_service.x.api_secret`, remove it.

## Key material: `jwk` blocks became one `jwks` string

This is the largest change, and the one worth planning.

In 1.3.x a service or client held a set of `jwk` blocks, one per key:

```terraform
jwk {
  kid      = "sig-1"
  alg      = "RS256"
  use      = "sig"
  generate = true
}
```

In 3.0 there is a single `jwks` attribute holding the JWK Set as a JSON string,
because that is what the API stores. Build it with `jsonencode` and the
provider's functions:

```terraform
jwks = jsonencode({
  keys = [jsondecode(provider::authlete::jwk_from_pem(
    tls_private_key.signing.private_key_pem, "sig-1", "RS256", "sig"))]
})
```

`federation_jwk` became `federation_jwks` in the same way.

### `generate = true` has no equivalent

1.3.x generated a key inside the provider at apply time and sent it to Authlete
without ever writing it to state. On read it returned your block unchanged, so
the private key existed only on the server.

3.0 cannot reproduce that. `jwks` is a single string attribute, and Terraform
stores a string attribute in state whole, so there is no per-key read-back to
suppress. Authlete 3.0 also has no endpoint that generates a key server-side.

You have two options, and the first is closer to what you had.

**Leave the key out of Terraform.** `jwks` is optional and computed, so a
configuration that does not mention it leaves whatever the server holds alone.
Create the key once in the Authlete console, then manage everything else about
the service normally:

```terraform
resource "authlete_service" "example" {
  service_name = "Example"
  issuer       = "https://example.com"
  # jwks deliberately absent: the keys are managed outside Terraform
}
```

A plan against a service whose keys were set this way reports no changes.

**Or generate the key with Terraform and keep it.** `hashicorp/tls` covers RSA,
ECDSA and Ed25519:

```terraform
resource "tls_private_key" "signing" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
```

This puts the private key in state, which the first option also does on
refresh. Either way, use a state backend that encrypts.

### X25519 needs an external tool

This provider converts an X25519 key into a JWK, but nothing generates the key
pair: `hashicorp/tls` offers RSA, ECDSA and Ed25519 and no X25519. If you used
`crv = "X25519"` with `generate = true`, generate the key outside Terraform:

```bash
openssl genpkey -algorithm X25519 -out x25519.pem
```

This needs OpenSSL 3.x. The LibreSSL that macOS ships refuses with
`Algorithm X25519 not found`.

Then:

```terraform
jwks = jsonencode({
  keys = [jsondecode(provider::authlete::jwk_from_pem(
    file("x25519.pem"), "ecdh-1", "ECDH-ES", "enc"))]
})
```

Or leave the key out of Terraform entirely, as above.

### Certificates and existing PEM keys

`pem_private_key` and `pem_certificate` on a `jwk` block become arguments to
`jwk_from_pem`. A key concatenated with its certificate chain produces `x5c`,
`x5t` and `x5t#S256`:

```terraform
provider::authlete::jwk_from_pem(
  "${file("server_key.pem")}${file("server_cert.pem")}",
  "sig-1", "RS256", "sig")
```

### Symmetric keys

1.3.x could hold one, by writing `kty = "oct"` and `k` into a `jwk` block by
hand, but it could not build one for you: its generator covered RSA, EC and
OKP only, and `HS256` was not in its list of accepted algorithms. 3.0 has
`jwk_from_secret`:

```terraform
provider::authlete::jwk_from_secret(var.shared_secret, "hmac-1", "HS256", "sig")
```

Use it on a service. Authlete holds the key for its own use and leaves it out
of the JWK Set it serves. A client is different: a client's JWK Set holds the
keys Authlete verifies that client with, so it must be public and asymmetric,
and a symmetric key sent to one is discarded.

### Some malformed key sets are refused before they are sent

Authlete stores a JWK Set without inspecting it, so 1.3.x would publish a key
that violated the specification and nothing would object. 3.0 refuses several
combinations at plan time:

- an algorithm the key cannot perform, such as `HS256` on an RSA key
- `alg` of `none`
- an ECDSA algorithm on the wrong curve, such as `ES256` on P-384
- two keys sharing a `kid`, or a key without one
- a `use` that is neither `sig` nor `enc`

A configuration that hits one of these was already producing a malformed key
set. Fix the key rather than working around the error.

The list is not exhaustive. A key set assembled by hand can still hold
contradictions these checks do not catch, and Authlete will store it.
`jwk_from_pem` and `jwk_from_secret` check more, because they see the key
rather than a document describing it.

## Client attributes moved into `extension`

Four attributes that were top-level on a client in 1.3.x now sit in the
`extension` object, matching the API:

```terraform
extension = {
  requestable_scopes_enabled = true
  requestable_scopes         = ["read", "write"]
  access_token_duration      = 3600
  refresh_token_duration     = 86400
}
```

`id_token_duration` and `token_exchange_permitted` live there too and are new.

### Requestable scopes are filtered by the service

A scope that the service does not define in `supported_scopes` is dropped by
Authlete without an error, on 1.3.x and on 3.0 alike. The apply succeeds, the
scope does not appear, and every later plan offers to add it again.

Define the scope on the service first. `requestable_scopes_enabled` must be
`true` for the restriction to apply at all.

Ordering does not matter for `requestable_scopes`. 1.3.x modelled it as a set,
where order never mattered; 3.0 models it as a list but compares it without
regard to order, so a list Authlete returns rearranged does not show a diff.

`supported_scopes` on a service is sorted by Authlete and is held the same way,
matched on scope name rather than on the whole entry, so an edit to a
description is still a change.

## What did not change

Attribute names outside the cases above follow the API, as they did in 1.3.x.
Scopes, grant types, response types, the mTLS subject attributes and the
endpoint settings all carry over by name.

The "Known limitations" guide covers behaviour that is expected rather than a
migration problem.
