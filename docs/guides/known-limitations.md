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

Change one attribute on a service or a client and the plan shows roughly 180
others as `(known after apply)`:

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

## Scope descriptions are filled in by Authlete

`supported_scopes` comes back from Authlete with fields set that a
configuration naming only the scope does not set, `default_entry` among them. A
plan may therefore offer to fill those in on the first apply after adding a
scope. Applying is harmless and the stored scopes are correct.

Ordering no longer causes a diff. Authlete sorts this list alphabetically, so a
configuration listing scopes in any other order used to show a change on every
plan, and dragged roughly 180 computed attributes into the plan with it. The
stored order is now held, matched on scope name, so an edit to a description
still shows as the change it is while a reordering shows nothing.

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

## Client secrets cannot be rotated in place

There is no Terraform equivalent of rotating a client secret. Authlete's API
supports it and the provider does not expose it.

Rotate in the Authlete console instead. The new secret is read back on the next
`terraform plan`, so state catches up on its own and nothing needs importing.

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

Define the scope on the service first. Note also that
`requestable_scopes_enabled` has to be `true` for the restriction to apply at
all. Authlete documents that with it `false` the client may request any scope
the service supports, whatever the list holds.

This is Authlete's behaviour rather than the provider's, and it was the same in
1.3.x. The provider cannot check it in advance when the service is managed
somewhere else.

## Undeclared custom metadata keys are discarded

Authlete keeps only the keys declared in the parent service's
`supported_custom_client_metadata`. A key set on a client that the service does
not declare is dropped: the apply succeeds, the key does not appear, and every
later plan offers to add it again.

Declare the key on the service before setting it on a client.

## Generated configuration for a client plans a follow-up change

`terraform plan -generate-config-out=generated.tf` works for both resources, and
for a client the plan afterwards shows an in-place update rather than nothing to
do.

The generated file is correct and complete. Some client fields are owned by
Authlete, `client_source` and `automatically_registered` among them, and cannot
appear in configuration, so Terraform reports them as not yet known. This is the
same behaviour as the first item on this page.
