# Contributing to This Repository

Thank you for your interest in contributing to this repository. Please note that this repository contains generated code. As such, we do not accept direct changes or pull requests. Instead, we encourage you to follow the guidelines below to report issues and suggest improvements.

## How to Report Issues

If you encounter any bugs or have suggestions for improvements, please open an issue on GitHub. When reporting an issue, please provide as much detail as possible to help us reproduce the problem. This includes:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected and actual behavior
- Any relevant logs, screenshots, or error messages
- Information about your environment (e.g., operating system, software versions)
    - For example can be collected using the `npx envinfo` command from your terminal if you have Node.js installed

## Issue Triage and Upstream Fixes

We will review and triage issues as quickly as possible. Our goal is to address bugs and incorporate improvements in the upstream source code. Fixes will be included in the next generation of the generated code.

## Contact

If you have any questions or need further assistance, please feel free to reach out by opening an issue.

Thank you for your understanding and cooperation!

The Maintainers

## Versioning and releases

The provider major is aligned with the Authlete API major it is generated
from. The 3.x line targets Authlete API 3.0, whose description declares
`version: 3.0.16`. The alignment was made once, at 3.0.0; after that the
provider versions on its own changes, so a later major does not imply a new
Authlete API. README.md carries the compatibility table that states the
mapping.

The published version is the git tag. `release.yml` fires on `v*` and
goreleaser builds `{{ .Version }}` from it. Nothing else decides what the
registry shows.

`.speakeasy/gen.yaml` holds a separate version that the generator copies into
`internal/sdk/authlete.go`, `examples/provider/provider.tf` and, from that
example, `docs/index.md`. A plain `speakeasy run` increments it on its own, so
between releases those files name a version nobody can install. That is
harmless because the registry renders the tagged commit, provided the tagged
commit was generated at the version being tagged.

So a release is two steps in this order:

```sh
speakeasy run --set-version 3.0.0   # same number, no leading v
git tag v3.0.0 && git push origin v3.0.0
```

`TestGeneratedVersionsAgree` fails if those files disagree with `gen.yaml`,
which catches a regeneration applied to some files and reverted in others.

A major of 2 or more needs a matching `/vN` suffix on the Go module path, and
the generator rewrites its own imports to use it. Changing the major means
changing `go.mod`, every import of the module, the `importLocation` entries in
`.speakeasy/gen.yaml` and the import paths in `.speakeasy/terraform_overlay.yaml`.
Miss any of them and the build fails inside the generator, reporting the
packages as missing from the published module rather than as a path mismatch.
`TestModulePathMatchesMajor` catches it first.

The README names no version at all. Its installation block is frozen against
regeneration, so a number in it would be maintained by hand and would go
stale; it points at the registry page instead.
