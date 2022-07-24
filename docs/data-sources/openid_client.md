---
page_title: "gluu_openid_client Data Source"
---

# gluu\_openid\_client Data Source

This data source can be used to fetch properties of a Gluu OpenID client for usage with other resources.

## Example Usage

```hcl
data "gluu_openid_client" "management" {
  client_id = "management"
}

```

## Argument Reference

- `client_id` - (Required) The client id (not its unique ID).

## Attributes Reference

See the docs for the `gluu_openid_client` resource for details on the exported attributes.
