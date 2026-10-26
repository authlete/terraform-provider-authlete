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

## If 1.3.x has started failing with a bare 400

This is not a migration problem, but it is the first thing people hit, and it
hits while still on 1.3.x:

```
Error: 400 Bad Request
```

1.3.x sends every URI attribute you left unset as an empty string, and Authlete
now rejects an empty URI with `A031219` where it accepts a missing one. Any
`apply` that creates or updates a service can fail this way, and the error does
not name the attribute.

Set the attribute to a real `https` URL to get past it:

```terraform
federation_registration_endpoint = "https://example.com/federation/register"
```

`federation_registration_endpoint` is the one usually responsible, but the same
applies to the other URI attributes. 3.0 sends an unset attribute as absent
rather than empty, so this stops once you have migrated.

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
  key_size = 2048
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

> ⚠️ **Setting `jwks` replaces the whole key set.** Any key not in the list is
> removed from the service. The examples here show one key because they are
> showing the syntax; a service with several keys needs all of them.
>
> This is easy to miss, because `jwks` is sensitive, so the plan shows only
> `~ jwks = (sensitive value)` and does not list the keys being deleted. If the
> service signs tokens with a key that disappears, and
> `id_token_signature_key_id` or one of the other key id attributes still names
> it, signing breaks.
>
> "Keeping the keys you already have", below, shows how to carry them across.

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

### Keeping the keys you already have

A 1.3.x service usually holds several keys: one or more that `generate = true`
produced, plus any you supplied as PEM. Writing a `jwks` with only the new key
deletes the rest.

First update the provider and rename your configuration for 3.0, leaving the
service's `jwks` unset while you preserve the existing keys. Save a refresh:

```shell
terraform apply -refresh-only
terraform plan
```

The refresh reads the existing keys from Authlete and saves state in the new
schema. Review the refresh before approving it, then expect the plan to show
no infrastructure changes. A normal `plan` alone does not save the upgraded
state; exporting it before this step can fail with a schema-version error.

Read the current set out of the refreshed state and add to it rather than
replacing it:

```shell
umask 077
terraform show -json | jq -r '
  .values.root_module.resources[]
  | select(.address == "authlete_service.example")
  | .values.jwks' > current-jwks.json
```

Then build the new set from both:

```terraform
jwks = jsonencode({
  keys = concat(
    jsondecode(file("current-jwks.json")).keys,
    [jsondecode(provider::authlete::jwk_from_pem(
      file("new-key.pem"), "sig-2", "RS256", "sig"))],
  )
})
```

That file holds private keys, and the configuration reads it on every plan, so
it has to stay where Terraform can find it. Do not delete it after the
migration: `file()` is evaluated every run, and a missing file fails every plan
and apply from then on.

Treat it as a secret for as long as it exists. Keep it out of version control,
restrict it to the user Terraform runs as, and give it the same handling as a
state file, which already holds the same keys. Every machine that runs a plan
reads it, so a pipeline has to fetch it from wherever secrets are kept and
write it beside the configuration before Terraform runs.

If that is more handling than you want, rotate instead of carrying the keys
over. Generate fresh keys with `tls_private_key`, set `jwks` to those alone,
and update whichever `*_signature_key_id` attributes name the old ones.
No exported key file is required, but the generated private keys still live
in Terraform state. It is a real rotation though: setting `jwks` replaces the
whole set, so the old keys are removed from Authlete. Existing tokens signed
by those keys stop verifying once a verifier no longer has them cached;
fetching the new set cannot restore a removed key. To avoid interrupting
verification, keep the old keys alongside the new ones until the tokens
signed by the old keys have expired.

Either way, check afterwards that every `*_signature_key_id` on the service
still names a `kid` that exists in `jwks`. Authlete does not check this, and a
name with no matching key is only noticed when signing fails.

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

As above, this replaces the whole set. An encryption key is usually added
beside signing keys rather than instead of them, so concatenate it with what
is already there.

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
- a symmetric key with no `k`, or one the wrong size for its algorithm
- a key type Authlete cannot read, which it drops silently
- a document that is not a JWK Set at all
- a private or symmetric key in a *client's* key set, which Authlete edits
  silently rather than refusing
- a private or symmetric key in a *trust anchor's* key set, which is a third
  party's and public by definition

A configuration that hits one of these was already producing a malformed key
set. Fix the key rather than working around the error.

The list is not exhaustive. A key set assembled by hand can still hold
contradictions these checks do not catch, and Authlete will store it.
`jwk_from_pem` and `jwk_from_secret` check more, because they see the key
rather than a document describing it.

A key set built from a value that is not known until plan time, a
`tls_private_key` reference for instance, is checked during the apply rather
than during the plan, but it is still checked before anything is sent.

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

## Attributes that are now read-only

Some attributes that 1.3.x let you set are server-owned in 3.0 and are reported
rather than configured. Setting one is refused by `terraform validate`, before
any plan and without a token:

```
Error: Invalid Configuration for Read-Only Attribute

  with authlete_client.c,
  on main.tf line 8, in resource "authlete_client" "c":
   8:   developer   = "someone"

Cannot set value for this attribute as the provider has marked it as
read-only. Remove the configuration line setting the value.
```

So this surfaces immediately rather than silently. Remove them from your
configuration; the values still read back, so anything referring to them keeps
working.

These nine were settable on a client in 1.3.17:

```
client_id                  developer
client_id_alias_enabled    dynamically_registered
client_secret              modified_at
created_at                 registration_access_token_hash
derived_sector_identifier
```

And these eleven on a service:

```
client_id_alias_enabled                       direct_jwks_endpoint_enabled
developer_authentication_callback_api_key     direct_revocation_endpoint_enabled
developer_authentication_callback_api_secret  direct_token_endpoint_enabled
developer_authentication_callback_endpoint    direct_user_info_endpoint_enabled
direct_authorization_endpoint_enabled         supported_acrs
direct_introspection_endpoint_enabled
```

Both lists are the intersection of what v1.3.17's schema accepted and what 3.0
marks read-only, taken from the two schemas rather than written by hand.

`developer` is the one most configurations carry: 1.3.x required it on
Authlete 2.x and rejected an empty value. `client_id_alias_enabled` is
deprecated and always true. `supported_acrs` is the one worth noticing, since
it is an ordinary setting rather than an identifier or a flag.

Other attributes are read-only in 3.0 too, but those did not exist in 1.3.17,
so nothing you are migrating can be setting them. The resource pages list them
under "Read-Only".

## What did not change

Attribute names outside the cases above follow the API, as they did in 1.3.x.
Scopes, grant types, response types, the mTLS subject attributes and the
endpoint settings all carry over by name.

The "Known limitations" guide covers behaviour that is expected rather than a
migration problem.
