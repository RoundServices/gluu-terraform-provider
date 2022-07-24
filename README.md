# gluu-terraform-provider

Terraform provider for [Gluu](https://gluu.org/).

## Docs

All documentation for this provider can now be found on the Terraform Registry: https://registry.terraform.io/providers/RoundServices/gluu/latest/docs

## Installation

This provider can be installed automatically using Terraform >=0.13 by using the `terraform` configuration block:

```hcl
terraform {
  required_providers {
    gluu = {
      source = "RoundServices/gluu"
      version = ">= 3.0.0"
    }
  }
}
```

If you are using Terraform 0.12, you can use this provider by downloading it and placing it within
one of the [implied local mirror directories](https://www.terraform.io/docs/commands/cli-config.html#implied-local-mirror-directories).
Or, follow the [old instructions for installing third-party plugins](https://www.terraform.io/docs/configuration-0-11/providers.html#third-party-plugins).

If you are using any provider version below v2.0.0, you can also follow the [old instructions for installing third-party plugins](https://www.terraform.io/docs/configuration-0-11/providers.html#third-party-plugins).

## Supported Versions

This provider will officially support the latest three major versions of Gluu, although older versions may still work.

The following versions are used when running acceptance tests in CI:

-

## Releases

This provider uses [GoReleaser](https://goreleaser.com/) to build and publish releases. Each release published to GitHub
contains binary files for Linux, macOS (darwin), and Windows, as configured within the [`.goreleaser.yml`](https://github.com/RoundServices/gluu-terraform-provider/blob/master/.goreleaser.yml)
file.

Each release also contains a `gluu-terraform-provider_${RELEASE_VERSION}_SHA256SUMS` file, accompanied by a signature
created by a PGP key with the fingerprint `C508 6791 5E11 6CD2`. This key can be found on my Keybase account at https://keybase.io/RoundServices.

You can find the list of releases [here](https://github.com/RoundServices/gluu-terraform-provider/releases).
You can find the changelog for each version [here](https://github.com/RoundServices/gluu-terraform-provider/blob/master/CHANGELOG.md).

Note: Prior to v2.0.0, a statically linked build for use within Alpine linux was included with each release. This is no longer
done due to [GoReleaser not supporting CGO](https://goreleaser.com/limitations/cgo/). Instead of using a statically linked,
build you can use the `linux_amd64` build as long as `libc6-compat` is installed.

## Development

This project requires Go 1.16 and Terraform >=0.13.
This project uses [Go Modules](https://github.com/golang/go/wiki/Modules) for dependency management, which allows this project to exist outside of an existing GOPATH.

After cloning the repository, you can build the project by running `make build`.

### Local Environment

You can spin up a local developer environment via [Docker Compose](https://docs.docker.com/compose/) by running `make local`.
This will spin up a few containers for Gluu, PostgreSQL, and OpenLDAP, which can be used for testing the provider.
This environment and its setup via `make local` is not intended for production use.

Note: The setup scripts require the [jq](https://stedolan.github.io/jq/) command line utility.

### Tests

Every resource supported by this provider will have a reasonable amount of acceptance test coverage.

You can run acceptance tests against a Gluu instance by running `make testacc`. You will need to supply some environment
variables in order to set up the provider during tests. Here is an example for running tests against a local environment
that was created via `make local`:

```
GLUU_CLIENT_ID=terraform \
GLUU_CLIENT_SECRET=884e0f95-0f42-4a63-9b1f-94274655669e \
GLUU_CLIENT_TIMEOUT=5 \
GLUU_URL="http://localhost:8080" \
make testacc
```

## License

[MIT](https://github.com/RoundServices/gluu-terraform-provider/blob/master/LICENSE)
