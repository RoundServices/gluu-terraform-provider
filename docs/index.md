---
page_title: "Gluu Provider"
---

# Gluu Provider

The Gluu provider can be used to interact with [Gluu](https://gluu.org/).

## Gluu Setup

This Terraform provider can be configured to use the [client credentials](https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/)
or [password](https://www.oauth.com/oauth2-servers/access-tokens/password-grant/) grant types. If you aren't
sure which to use, the client credentials grant is recommended, as it was designed for machine to machine authentication.

### Client Credentials Grant Setup (recommended)

1. Create a new client using the `openid-connect` protocol.
1. Update the client you just created:
    1. Set `Access Type` to `confidential`.
    1. Set `Standard Flow Enabled` to `OFF`.
    1. Set `Direct Access Grants Enabled` to `OFF`
    1. Set `Service Accounts Enabled` to `ON`.
1. Grant required roles for managing Gluu via the `Service Account Roles` tab in the client you created in step 1, see [Assigning Roles](#assigning-roles) section below.

### Password Grant Setup

These steps will assume that you are using the `admin-cli` client, which is already correctly configured for this type
of authentication. Do not follow these steps if you have already followed the steps for the client credentials grant.

1. Create or identify the user whose credentials will be used for authentication.
1. Edit this user in the "Users" section of the management console and assign roles using the "Role Mappings" tab.

### Assigning Roles

There are many ways that roles can be assigned to manage Gluu. Here are a couple of common scenarios accompanied
by suggested roles to assign. This is not an exhaustive list, and there is often more than one way to assign a particular set
of permissions.

- Managing the entire Gluu instance: Assign the `admin` role to a user or service account.

## Example Usage (client credentials grant)

```hcl
provider "gluu" {
	client_id     = "terraform"
	client_secret = "884e0f95-0f42-4a63-9b1f-94274655669e"
	url           = "http://localhost:8080"
}
```

## Example Usage (password grant)

```hcl
provider "gluu" {
	client_id     = "admin-cli"
	username      = "gluu"
	password      = "password"
	url           = "http://localhost:8080"
}
```

## Argument Reference

The following arguments are supported:

- `client_id` - (Required) The `client_id` for the client that was created in the "Gluu Setup" section. Use the `admin-cli` client if you are using the password grant. Defaults to the environment variable `GLUU_CLIENT_ID`.
- `url` - (Required) The URL of the Gluu instance, before `/auth/admin`. Defaults to the environment variable `GLUU_URL`.
- `client_secret` - (Optional) The secret for the client used by the provider for authentication via the client credentials grant. This can be found or changed using the "Credentials" tab in the client settings. Defaults to the environment variable `GLUU_CLIENT_SECRET`. This attribute is required when using the client credentials grant, and cannot be set when using the password grant.
- `username` - (Optional) The username of the user used by the provider for authentication via the password grant. Defaults to the environment variable `GLUU_USER`. This attribute is required when using the password grant, and cannot be set when using the client credentials grant.
- `password` - (Optional) The password of the user used by the provider for authentication via the password grant. Defaults to the environment variable `GLUU_PASSWORD`. This attribute is required when using the password grant, and cannot be set when using the client credentials grant.
- `initial_login` - (Optional) Optionally avoid Gluu login during provider setup, for when Gluu itself is being provisioned by terraform. Defaults to true, which is the original method.
- `client_timeout` - (Optional) Sets the timeout of the client when addressing Gluu, in seconds. Defaults to the environment variable `GLUU_CLIENT_TIMEOUT`, or `5` if the environment variable is not specified.
- `tls_insecure_skip_verify` - (Optional) Allows ignoring insecure certificates when set to `true`. Defaults to `false`. Disabling this security check is dangerous and should only be done in local or test environments.
- `root_ca_certificate` - (Optional) Allows x509 calls using an unknown CA certificate (for development purposes)
- `base_path` - (Optional) The base path used for accessing the Gluu REST API.  Defaults to the environment variable `GLUU_BASE_PATH`, or `/auth` if the environment variable is not specified. Note that users of the new Quarkus distribution will need to set this attribute to an empty string.
- `additional_headers` - (Optional) A map of custom HTTP headers to add to each request to the Gluu API.
