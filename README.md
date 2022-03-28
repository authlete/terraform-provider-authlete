# Terraform Provider Scaffolding

This is a Terraform provider for managing configuration of your [Authlete](https://www.authlete.com) OAuth 2 and OpenID Connect services and clients.

⚠️ This provider is **currently under active development** and is not GA. Using it for live production services is not adviced, yet.

👉 Authlete servers version 2.2+ are supported. (This includes the shared server at api.authlete.com)

## Requirements

- [Authlete account](https://so.authlete.com/accounts/signup)
- [Terraform](https://www.terraform.io/downloads.html) >= 0.13.x
- [Go](https://golang.org/doc/install) >= 1.15


## Building The Provider

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the `make install` command:
```sh
$ go mod tidy
$ make install
```

## Using the provider

This provider support managing the services and its configuration from terraform script.

The provider can also generate random RSA and EC (including Ed25519 and  X235519) keys that will reside only on Authlete side.

## Developing the Provider

If you wish to work on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (see [Requirements](#requirements) above).

To compile the provider, run `go install`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

To generate or update documentation, run `go generate`.

In order to run the full suite of Acceptance tests, run `make testacc`.

*Note:* Acceptance tests create real resources, and often cost money to run.

```sh
$ export AUTHLETE_API_SERVER="https://api.authlete.com"
$ export AUTHLETE_SO_SECRET="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
$ export AUTHLETE_SO_KEY="XXXXXXXXXXXXXX"
$ make testacc
```
