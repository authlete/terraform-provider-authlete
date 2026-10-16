---
page_title: "Known limitations"
subcategory: ""
description: |-
  Behaviour that looks like a defect but is expected, and what to do instead.
---

# Known limitations

Each of these is known, deliberate, and will look like a bug the first time you
meet it. None of them prevents the provider from managing a service or a client
correctly.

## Plans show many attributes as "known after apply"

Change one attribute on a service or a client and the plan shows most of the
others as `(known after apply)`. Measured on a service: 178 of them for a
single rename.

```
~ service_name = "example" -> "example-renamed"
~ metadata     = [ ... ]   -> (known after apply)
~ modified_at  = 1791977830000 -> (known after apply)
# and so on
```

**Nothing is changing in those.** Authlete computes them, and Terraform cannot
know what the API will return until the apply has happened, so it reports them
as not yet known rather than guessing.

The values are correct afterwards, and resources that depend on this one are not
dragged into the change: identifiers, timestamps and secrets are stable, so a
module consuming a client secret plans nothing when the service is edited. The
plan output is simply verbose.

## Scope order is not the order you wrote

Authlete sorts `supported_scopes` alphabetically, so what it stores is not the
order in your configuration:

```
configured: zeta, alpha, mike, beta
stored:     alpha, beta, mike, zeta
```

This no longer causes a diff. The configured order is held in state, matched
on scope name, so a reordering shows nothing while an edit to a description
still shows as the change it is. It is worth knowing only because the Authlete
console lists the scopes in its own order rather than yours.

## Private keys are held in Terraform state

A service's `jwks` is one string attribute, and Terraform stores a string
attribute in state whole. Any private key in that key set is therefore in your
state file, whether you built it with `jwk_from_pem`, pasted it in, or never
mentioned it at all: `jwks` is computed, so a refresh reads back whatever
Authlete holds.

Use a state backend that encrypts at rest. The attribute is marked sensitive,
so it does not appear in plan output, but that governs the console and not the
file.

Leaving `jwks` out of your configuration keeps the key out of version control,
which is worth doing, but it does not keep it out of state.

## Client secrets are rotated outside Terraform

A client secret can be rotated, but not from Terraform. `client_secret` is
computed, so there is nothing to set, and the provider exposes neither of the
two API operations that change it.

Rotate in the Authlete console instead, and leave your configuration alone.
Terraform notices on the next plan and proposes nothing:

```
~ client_secret = (sensitive value)
```

The plan carries Terraform's standard warning that it "may include actions to
undo or respond to these changes". It does not here, because the attribute is
computed: no action is proposed against the client. State catches up on the
next `terraform apply` or `terraform apply -refresh-only`, since a plan reports
drift without writing state. Running only plans leaves the notice showing.

Replacing the resource would also produce a new secret, but it changes the
`client_id` too, which breaks every integration pointing at that client. Do not
use that as a substitute.

## Removing a setting does not reset it

Deleting an attribute from your configuration means you no longer have an
opinion about it, not that it should return to its default. The value stays as
you last set it.

To clear something, set it explicitly:

```terraform
supported_displays = []   # supports none
description        = ""   # empty
```

This is standard Terraform rather than anything specific to Authlete, but it
catches people out. The one exception is the mutually exclusive certificate
subject types, `tls_client_auth_subject_dn` and the four
`tls_client_auth_san_*` attributes: Authlete accepts exactly one, so naming a
different one clears the previous one for you.

## Requestable scopes the service does not define are discarded

A client's `requestable_scopes` is filtered to the scopes the parent service
lists in `supported_scopes`. Anything else is dropped without an error: the
apply succeeds, the scope does not appear, and every later plan offers to add
it again.

```terraform
requestable_scopes = ["read", "admin"]   # service defines only "read"
```

leaves `["read"]` stored, and `admin` comes back as a diff for ever.

Define the scope on the service first.

`requestable_scopes_enabled` has to be `true` for the list to restrict
anything. Measured against a live token request, for a client whose
`requestable_scopes` is `["read"]` and a service defining `read`, `write` and
`admin`:

| `requestable_scopes_enabled` | asked for | granted |
|---|---|---|
| `true` | `read write admin` | `read` |
| `false` | `read write admin` | `read write admin` |

So the list is inert while the flag is `false`, and a client left that way is
not restricted at all. The service's `supported_scopes` still bounds it either
way: asking for a scope the service does not define grants nothing for that
scope, whatever the flag says.

This is Authlete's behaviour rather than the provider's, and it was the same in
1.3.x. The provider cannot check it in advance when the service is managed
somewhere else.

## Undeclared custom metadata keys are discarded

Authlete keeps only the keys declared in the parent service's
`supported_custom_client_metadata`. A key set on a client that the service does
not declare is dropped: the apply succeeds, the key does not appear, and every
later plan offers to add it again. Measured, sending both at once:

```
sent:   {"declared_key":"kept","undeclared_key":"dropped"}
stored: {"declared_key":"kept"}
```

Declare the key on the service before setting it on a client.
