# v3.0.0-beta3

This beta brings back what 1.3.x users relied on for keys and certificates,
fixes plans that never settled, and stops a service deleted outside Terraform
from blocking every plan. It also refuses many key mistakes at plan time that
Authlete would otherwise store, change or drop without saying so.

Pin the exact version. Terraform never selects a pre-release for a range such
as `~> 3.0`:

```terraform
terraform {
  required_providers {
    authlete = {
      source  = "authlete/authlete"
      version = "3.0.0-beta3"
    }
  }
}
```

Coming from 1.3.x? Read the [migration guide](https://registry.terraform.io/providers/authlete/authlete/3.0.0-beta3/docs/guides/migrating-from-1-3)
first. Key generation, `jwk` blocks and `api_secret` work differently in 3.x.

## Breaking changes from 3.0.0-beta2

- **`api_secret` is removed from `authlete_service`.** Authlete 3.0 never
  returns it, so it always resolved to null. Remove any output or reference
  to it. API calls authenticate with an Organization Token or a Service
  Access Token.
- **Key sets are checked at plan time.** A configuration that applied on
  beta2 can now fail to plan if its `jwks`, or a `jwk_from_pem` call, holds
  something Authlete would store wrongly, change or drop. The error names the
  key and the problem. See [Key checks](#key-checks) below.
- **A client's `jwks` must hold public keys only.** A private key or a
  symmetric key in a client's key set is now refused. On beta2, Authlete
  stripped the private half or dropped the symmetric key without an error, and
  the plan never settled. Pass the client's public key or certificate to
  `jwk_from_pem`. For a shared secret, use the client secret.

## New

- **`jwk_from_secret`** builds a symmetric JWK from a shared secret, for HMAC
  signing (`HS256`, `HS384`, `HS512`) or encryption (`A128KW` and the other
  AES key wraps, `dir`, `PBES2`). It replaces the
  `replace(replace(replace(base64encode(...))))` workaround. The secret's
  length is checked against the algorithm.
- **Certificates in `jwk_from_pem`.** Pass a certificate, or a key followed
  by its certificate chain, and the JWK carries `x5c` (leaf first) with both
  thumbprints, `x5t` and `x5t#S256`. This replaces 1.3.x's `pem_certificate`.
- **X25519 keys in `jwk_from_pem`**, for `ECDH-ES` encryption. `hashicorp/tls`
  cannot generate X25519, so generate the key with `openssl genpkey -algorithm
  X25519`. Note that macOS ships LibreSSL, which refuses with `Algorithm X25519
  not found`; use a real OpenSSL build.
- **Migration guide** for moving from 1.3.x, and an expanded **Known
  limitations** page.

## Fixed

- **A service deleted outside Terraform no longer blocks every plan.**
  Authlete reports a missing service with a 403, which beta2 treated as an
  error, so every plan failed until the resource was removed from state by
  hand. It is now planned for recreation, as Terraform expects. The data
  sources now say `Service <id> does not exist` instead of printing an HTTP
  dump.
- **Plans that never settled because of list order.** Authlete returns some
  lists in its own order, so a configuration listing them in any other order
  showed a change on every plan, and dragged 178 computed attributes
  into the plan as "known after apply". The order you write is now kept for:
  - `supported_scopes` on the service
  - `requestable_scopes` in a client's `extension`
  - `supported_introspection_auth_methods`, `supported_revocation_auth_methods`
    and `supported_backchannel_token_delivery_modes`
  - `fapi_modes` on the service and the client, and
    `supported_client_registration_types`

  A test now fails if a new enumerated list arrives without this, rather than
  waiting for someone to hit it in a plan.

## Key checks

These are refused at plan time, before anything is sent to Authlete:

- An algorithm the key cannot perform, such as `HS256` on an RSA key or
  `EdDSA` on X25519, and `alg = "none"`
- An algorithm that does not fit the `use`, such as `RS256` for encryption
- A key type Authlete does not recognise, including a misspelling such as
  `"rsa"`, or no `kty` at all. Authlete drops such a key without an error.
- A key with no `kid`, or two keys sharing one
- A symmetric key of the wrong length for its algorithm, with no `k`, or with
  a `k` that is not base64url
- EC or OKP coordinates that are not the full width of the curve
- An `x5c` entry that is not standard base64 or not a certificate
- A document that is not a JWK Set
- In a client's key set, a private or symmetric key

A key set built from a value that is not known until apply, such as a
`tls_private_key` reference, is checked during the apply instead, still before
anything is sent.

`jwk_from_pem` and `jwk_from_secret` accept only the algorithms they know.
A hand-written JWK in `jwks` accepts an unrecognised algorithm name, so that
a new Authlete algorithm works without a provider release.

`jwk_from_pem` also refuses two keys in one input, and a certificate that does
not belong to the key it is paired with. An encrypted private key is refused
too, as `could not parse "ENCRYPTED PRIVATE KEY" block`; decrypt it first.

## Known limitations

See the [Known limitations](https://registry.terraform.io/providers/authlete/authlete/3.0.0-beta3/docs/guides/known-limitations)
page. The ones most likely to surprise you:

- Private keys and secrets are held in Terraform state. Use a state backend
  that encrypts at rest.
- Client secrets are rotated outside Terraform, in the Management Console.
  Terraform notices the new secret and proposes no action; state catches up on
  the next apply or refresh. Do not use `terraform apply -replace` as a
  substitute, because it changes the `client_id` too.
- A client's `requestable_scopes` restricts it only when
  `requestable_scopes_enabled = true`. With the flag `false` the list has no
  effect and the client can be granted any scope the service supports.
- A requestable scope the service does not define is dropped by Authlete
  without an error. Define it in the service's `supported_scopes` first.
- Keys are not generated on the server in Authlete 3.0. Use `hashicorp/tls`
  for RSA, ECDSA and Ed25519, and OpenSSL for X25519.
