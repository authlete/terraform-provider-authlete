# Manual test harness

Exercises the locally built provider against Authlete without publishing it to
the Terraform registry. `run.sh` builds `../` into `.provider-bin/`, writes a
`dev_overrides` block to a throwaway CLI config in this directory, and points
Terraform at it via `TF_CLI_CONFIG_FILE`. Your `~/.terraformrc` is left alone.

`dev_overrides` bypasses the registry for the Authlete provider, but `main.tf`
also uses `hashicorp/tls` to generate a signing key, and that one is a real
registry provider. So the first run in a fresh checkout does a `terraform init`
automatically; later runs skip it. Terraform prints a "development overrides are
in effect" warning on every command; that is expected.

## Usage

```bash
./run.sh validate    # provider loads, schema and config agree — no token, no API calls
./run.sh plan        # default; no API calls, because nothing exists in state yet
./run.sh apply       # creates a real service + client; prompts first
./run.sh destroy     # removes what apply created
./run.sh show        # dump current state
```

`validate` and `plan` work with no credentials at all — Terraform only needs the
API once it has to reconcile something that exists. `apply` and `destroy` refuse
to run without a token.

## Configuration

| Variable | Purpose |
|---|---|
| `AUTHLETE_TOKEN` | Read directly by the provider. Required for `apply`/`destroy`. Must be an **Organization Token** — a Service Access Token is scoped to one existing service and cannot create one. |
| `AUTHLETE_ORGANIZATION_ID` | Required for `apply`/`destroy`. The IdP create endpoint will not accept a service without it. |
| `AUTHLETE_SERVER_URL` | Read directly by the provider. Defaults to `https://us.authlete.com`; set `https://jp.authlete.com` for the JP cluster. |
| `AUTHLETE_IDP_HOST` | Only for Dedicated Cloud and On-Premise, which run their own IdP. Unset means Authlete's shared cloud. |
| `AUTHLETE_NAME_PREFIX` | Defaults to `tftest`. Prefixes created object names so test artifacts are identifiable. |

Values can go in a gitignored `.env.local` beside this file, which `run.sh`
sources automatically; anything already exported wins, so you can override a
single value for one run.

```bash
export AUTHLETE_TOKEN='...' AUTHLETE_ORGANIZATION_ID='...'
./run.sh apply
```

`AUTHLETE_TOKEN` and `AUTHLETE_SERVER_URL` are consumed by the provider itself, so `main.tf`
declares `provider "authlete" {}` with no credential in configuration at all. The provider block
also accepts `idp_host`, `tls_skip_verify` and `http_headers`.

`api_server_id` no longer needs setting: the provider derives it from the cluster URL and injects
it into IdP requests. Self-managed clusters it cannot map should still set it on the resource.

### Service quota

A free-trial organization allows **one service**. If that slot is occupied, `apply` fails with
`403 To create more services, upgrade your plan.` — which is a plan limit, not a provider fault.
Check what exists before assuming a regression:

```bash
curl -s -H "Authorization: Bearer $AUTHLETE_TOKEN" \
  "$AUTHLETE_SERVER_URL/api/service/get/list"
```

## What it covers

`main.tf` creates a service, creates a client underneath it, then reads both
back through the data sources — so the read path is exercised separately from
the resources' own state rather than trusting what create returned.

Two asymmetries in the generated schema are worth knowing, both consequences of
how the entity annotations in `.speakeasy/terraform_overlay.yaml` map onto the
spec:

- `authlete_service` exports `api_key` as a **Number**, while
  `authlete_client.service_id` is a **String**, so wiring them needs
  `tostring()`. Only `clientId` was retyped in the overlay; the client
  endpoints still type `serviceId` as a string.
- The `authlete_service` **data source** keys off `api_key`, not `service_id` —
  `x-speakeasy-match: apiKey` folded the path parameter into that attribute. The
  client data source still takes a separate `service_id`.

## Verified status

The full lifecycle has been exercised against a live JP-cluster org:

```
authlete_service.test: Creation complete after 2s
authlete_client.test:  Creation complete after 1s
Apply complete! Resources: 2 added
terraform plan  -> No changes. Your infrastructure matches the configuration.
Destroy complete! Resources: 2 destroyed
```

The clean re-plan matters more than the apply: generated providers routinely
produce perpetual diffs when response fields do not round-trip into state, and
this one does not.

## Which service endpoint gets used, and why it matters

Authlete has two service-creation endpoints, and only one of them works:

| Endpoint | Host | Body | Usable? |
|---|---|---|---|
| `POST /api/service` | `login.authlete.com` (IdP) | `apiServerId` + `organizationId` + nested `service` | yes |
| `POST /api/service/create` | regional cluster | bare `service` | no |

The cluster endpoint returns 200 with a real `apiKey`, but the service it creates
is attached to no organization. The IdP cannot find it under any `apiServerId`, it
never reaches the audit log, and every service-scoped call afterwards fails:

```
[A457101] Function requires access rights ([CREATE_CLIENT]) for service (...),
access token does not have sufficient access.
```

It also cannot be deleted, by either host. The overlay therefore annotates the
IdP endpoint for `Service#create` and `POST /api/service/remove` for
`Service#delete`, and deliberately leaves the cluster's create and delete
unannotated. `Service#read` and `Service#update` stay on the cluster, which has
no IdP equivalent.

This split is why the service resource needs `organization_id` and
`api_server_id`, and why `gen.yaml` sets `enableOperationServers: true`. The
generated SDK hardcodes `https://login.authlete.com` for the two IdP operations,
so the provider's `server_url` correctly affects only the cluster calls.

## Caveat

This directory is hand-written and is not tracked in `.speakeasy/gen.lock`, so
`speakeasy run` leaves it alone. Nothing here is generated; edit it freely.
