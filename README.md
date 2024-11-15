# Terraform Provider Scaffolding

This is a Terraform provider for managing configuration of your [Authlete](https://www.authlete.com) OAuth 2 and OpenID Connect services and clients.

👉 Authlete servers version 2.2+ are supported. (This includes the shared server at api.authlete.com)

## Requirements

- [Authlete account](https://login.authlete.com/signup)
- [Terraform](https://www.terraform.io/downloads.html) >= 0.13.x
- [Go](https://golang.org/doc/install) >= 1.17


## Building The Provider

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the `make install` command:
```sh
$ go mod tidy
$ make install
```

## Using the provider

Checkout the documentation on [Authlete website](https://www.authlete.com/developers/terraform/) on how to use this
provider


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
