---
page_title: "Known limitations"
subcategory: ""
description: |-
  Behaviour that looks like a defect but is expected, and what to do instead.
---

# Known limitations

Each of these is known and will look like a bug the first time you meet it.
None of them prevents the provider from managing a service or a client
correctly, and only the first can cost you anything: read that one before your
first destroy.

Most are deliberate and will not change. A few are defects awaiting a fix, and
those say so and name the release that removes the need for the workaround.
Where the workaround is `ignore_changes`, take it out again once that release
is in place: left behind, it goes on hiding real drift on that attribute long
after the reason for it has gone.

## Destroying a service destroys every client under it

A client belongs to a service, and Authlete deletes the clients with it. That
includes clients this configuration has never seen: ones created in the
console, through Dynamic Client Registration, or by another team.

So the blast radius of

```bash
terraform destroy -target=authlete_service.my_service
```

is the whole authorization server, not the one resource named on the command
line, and Terraform's plan cannot show you the part it does not know about. It
lists the clients in your state and nothing else.

This is how Authlete works and the provider does not change it. Before
destroying a service, look at its client list in the console.

The provider does guard the related mistake. A destroy aimed at the wrong
cluster, organization or identity server is refused rather than carried out,
and the error names the setting that disagrees. That protects you from
deleting a service you did not mean to reach. It cannot protect you from
deleting the one you did mean to reach, which is what this section is about.

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

## Translated names and URIs are stored but not read back

A client's localised attributes are accepted, saved by Authlete and then left
out of every read:

- `client_names`
- `logo_uris`
- `client_uris`
- `policy_uris`
- `tos_uris`
- `descriptions`

So the value is applied correctly and the server holds it, but the refresh
brings back nothing and the next plan offers the same change again. After
`terraform import` the attributes are empty even though the console shows them.

This is a server defect, fixed but not yet released, so the provider cannot
work around it: there is nothing in the response to read. Until the fix ships,
either accept the repeating diff, which applies harmlessly, or hold the
attributes out of the comparison:

```terraform
resource "authlete_client" "my_client" {
  # ...
  lifecycle {
    ignore_changes = [client_names, logo_uris]
  }
}
```

`ignore_changes` here stops Terraform noticing a later edit to those attributes
too, so remove it once the server fix is in place.

Most likely to affect you if you serve Japanese end users, since the localised
entry is the one that carries the translation.

## A description on a standard scope is replaced by Authlete's own

Set `description` on a scope Authlete defines itself, `openid` for instance,
and the server stores its own wording instead. The apply succeeds, the scope is
correct in every other respect, and the next plan offers your description
again.

Leave the description unset on standard scopes. Your own scopes keep whatever
you write:

```terraform
supported_scopes = [
  { name = "openid" },                                        # no description
  { name = "payments", description = "Initiate a payment" },  # kept
]
```

A fix is expected in a patch release. Until then an explicit description on a
standard scope is the one thing to avoid, rather than something to work around.

## Secrets and private keys are held in Terraform state

Terraform stores every attribute in state, and a string attribute whole. Seven
attributes hold key material or a shared secret, so each of them is in your
state file in plain text:

| Attribute | Where |
| --- | --- |
| `jwks` | `authlete_service` |
| `federation_jwks` | `authlete_service` |
| `credential_jwks` | `authlete_service` |
| `authentication_callback_api_secret` | `authlete_service` |
| `developer_authentication_callback_api_secret` | `authlete_service` |
| `client_secret` | `authlete_client` |
| `http_headers` | provider configuration |

This holds whether you set the value, built it with `jwk_from_pem`, or never
mentioned it: all of these are computed, so a refresh reads back whatever
Authlete holds.

**Use a state backend that encrypts at rest.** Everything above except
`http_headers` is marked sensitive, so it does not appear in plan output, but
that governs the console and not the file. Leaving an attribute out of your
configuration keeps it out of version control, which is worth doing, but it
does not keep it out of state.

Two key sets are deliberately absent from that list. A client's `jwks` and a
trust anchor's are public by contract, and the provider refuses private
material in either at plan time, so neither can carry a secret into state.

### `http_headers` in particular

`http_headers` sets headers on every request the provider makes, and some
deployments use it to carry a gateway credential. Those values are masked in
`TF_LOG=DEBUG` output alongside client secrets and private key sets, but the
attribute is not marked sensitive, so the value appears in plan output as well
as in state.

A gateway credential that must not reach a state file is better supplied to the
pipeline directly than through the provider.

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
