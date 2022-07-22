---
page_title: "gluu_openid_client Resource"
---

# gluu\_openid\_client Resource

Allows for creating and managing Gluu clients that use the OpenID Connect protocol.

Clients are entities that can use Gluu for user authentication. Typically,
clients are applications that redirect users to Gluu for authentication
in order to take advantage of Gluu's user sessions for SSO.

## Example Usage

```hcl
resource "gluu_realm" "realm" {
  realm   = "my-realm"
  enabled = true
}

resource "gluu_openid_client" "openid_client" {
  realm_id            = gluu_realm.realm.id
  client_id           = "test-client"

  name                = "test client"
  enabled             = true

  access_type         = "CONFIDENTIAL"
  valid_redirect_uris = [
    "http://localhost:8080/openid-callback"
  ]

  login_theme = "gluu"

  extra_config = {
    "key1" = "value1"
    "key2" = "value2"
  }
}
```

## Argument Reference

- `realm_id` - (Required) The realm this client is attached to.
- `client_id` - (Required) The Client ID for this client, referenced in the URI during authentication and in issued tokens.
- `name` - (Optional) The display name of this client in the GUI.
- `enabled` - (Optional) When `false`, this client will not be able to initiate a login or obtain access tokens. Defaults to `true`.
- `description` - (Optional) The description of this client in the GUI.
- `access_type` - (Required) Specifies the type of client, which can be one of the following:
  - `CONFIDENTIAL` - Used for server-side clients that require both client ID and secret when authenticating.
      This client should be used for applications using the Authorization Code or Client Credentials grant flows.
  - `PUBLIC` - Used for browser-only applications that do not require a client secret, and instead rely only on authorized redirect
      URIs for security. This client should be used for applications using the Implicit grant flow.
  - `BEARER-ONLY` - Used for services that never initiate a login. This client will only allow bearer token requests.
- `client_secret` - (Optional) The secret for clients with an `access_type` of `CONFIDENTIAL` or `BEARER-ONLY`. This value is sensitive and should be treated with the same care as a password. If omitted, this will be generated by Gluu.
- `client_authenticator_type` - (Optional) Defaults to `client-secret` The authenticator type for clients with an `access_type` of `CONFIDENTIAL` or `BEARER-ONLY`. Can be one of the following:
  - `client-secret` (Default) Use client id and client secret to authenticate client.
  - `client-jwt` Use signed JWT to authenticate client. Set signing algorithm in `extra_config` with `attributes.token.endpoint.auth.signing.alg = <alg>`
  - `client-x509` Use x509 certificate to authenticate client. Set Subject DN in `extra_config` with `attributes.x509.subjectdn = <subjectDn>`
  - `client-secret-jwt` Use signed JWT with client secret to authenticate client. Set signing algorithm in `extra_config` with `attributes.token.endpoint.auth.signing.alg = <alg>`
- `standard_flow_enabled` - (Optional) When `true`, the OAuth2 Authorization Code Grant will be enabled for this client. Defaults to `false`.
- `implicit_flow_enabled` - (Optional) When `true`, the OAuth2 Implicit Grant will be enabled for this client. Defaults to `false`.
- `direct_access_grants_enabled` - (Optional) When `true`, the OAuth2 Resource Owner Password Grant will be enabled for this client. Defaults to `false`.
- `service_accounts_enabled` - (Optional) When `true`, the OAuth2 Client Credentials grant will be enabled for this client. Defaults to `false`.
- `frontchannel_logout_enabled` - (Optional) When `true`, frontchannel logout will be enabled for this client. Specify the url with `frontchannel_logout_url`. Defaults to `false`.
- `frontchannel_logout_url` - (Optional) The frontchannel logout url. This is applicable only when `frontchannel_logout_enabled` is `true`.
- `valid_redirect_uris` - (Optional) A list of valid URIs a browser is permitted to redirect to after a successful login or logout. Simple
wildcards in the form of an asterisk can be used here. This attribute must be set if either `standard_flow_enabled` or `implicit_flow_enabled`
is set to `true`.
- `web_origins` - (Optional) A list of allowed CORS origins. To permit all valid redirect URIs, add `+`. Note that this will not include the `*` wildcard. To permit all origins, explicitly add `*`."
- `root_url` - (Optional) When specified, this URL is prepended to any relative URLs found within `valid_redirect_uris`, `web_origins`, and `admin_url`. NOTE: Due to limitations in the Gluu API, when the `root_url` attribute is used, the `valid_redirect_uris`, `web_origins`, and `admin_url` attributes will be required.
- `admin_url` - (Optional) URL to the admin interface of the client.
- `base_url` - (Optional) Default URL to use when the auth server needs to redirect or link back to the client.
- `pkce_code_challenge_method` - (Optional) The challenge method to use for Proof Key for Code Exchange. Can be either `plain` or `S256` or set to empty value ``.
- `full_scope_allowed` - (Optional) Allow to include all roles mappings in the access token.
- `access_token_lifespan` - (Optional) The amount of time in seconds before an access token expires. This will override the default for the realm.
- `client_offline_session_idle_timeout` - (Optional) Time a client session is allowed to be idle before it expires. Tokens are invalidated when a client session is expired. If not set it uses the standard SSO Session Idle value.
- `client_offline_session_max_lifespan` - (Optional) Max time before a client session is expired. Tokens are invalidated when a client session is expired. If not set, it uses the standard SSO Session Max value.
- `client_session_idle_timeout` - (Optional) Time a client offline session is allowed to be idle before it expires. Offline tokens are invalidated when a client offline session is expired. If not set it uses the Offline Session Idle value.
- `client_session_max_lifespan` - (Optional) Max time before a client offline session is expired. Offline tokens are invalidated when a client offline session is expired. If not set, it uses the Offline Session Max value.
- `consent_required` - (Optional) When `true`, users have to consent to client access. Defaults to `false`.
- `display_on_consent_screen` - (Optional) When `true`, the consent screen will display information about the client itself. Defaults to `false`. This is applicable only when `consent_required` is `true`.
- `consent_screen_text` - (Optional) The text to display on the consent screen about permissions specific to this client. This is applicable only when `display_on_consent_screen` is `true`.
- `authentication_flow_binding_overrides` - (Optional) Override realm authentication flow bindings
  - `browser_id` - (Optional) Browser flow id, (flow needs to exist)
  - `direct_grant_id` - (Optional) Direct grant flow id (flow needs to exist)
- `login_theme` - (Optional) The client login theme. This will override the default theme for the realm.
- `exclude_session_state_from_auth_response` - (Optional) When `true`, the parameter `session_state` will not be included in OpenID Connect Authentication Response.
- `use_refresh_tokens` - (Optional) If this is `true`, a refresh_token will be created and added to the token response. If this is `false` then no refresh_token will be generated.  Defaults to `true`.
- `use_refresh_tokens_client_credentials` - (Optional) If this is `true`, a refresh_token will be created and added to the token response if the client_credentials grant is used and a user session will be created. If this is `false` then no refresh_token will be generated and the associated user session will be removed, in accordance with OAuth 2.0 RFC6749 Section 4.4.3. Defaults to `false`.
- `oauth2_device_authorization_grant_enabled` - (Optional) Enables support for OAuth 2.0 Device Authorization Grant, which means that client is an application on device that has limited input capabilities or lack a suitable browser.
- `oauth2_device_code_lifespan` - (Optional) The maximum amount of time a client has to finish the device code flow before it expires.
- `oauth2_device_polling_interval` - (Optional) The minimum amount of time in seconds that the client should wait between polling requests to the token endpoint.
- `authorization` - (Optional) When this block is present, fine-grained authorization will be enabled for this client. The client's `access_type` must be `CONFIDENTIAL`, and `service_accounts_enabled` must be `true`. This block has the following arguments:
  - `policy_enforcement_mode` - (Required) Dictates how policies are enforced when evaluating authorization requests. Can be one of `ENFORCING`, `PERMISSIVE`, or `DISABLED`.
  - `decision_strategy` - (Optional) Dictates how the policies associated with a given permission are evaluated and how a final decision is obtained. Could be one of `AFFIRMATIVE`, `CONSENSUS`, or `UNANIMOUS`. Applies to permissions.
  - `allow_remote_resource_management` - (Optional) When `true`, resources can be managed remotely by the resource server. Defaults to `false`.
  - `keep_defaults` - (Optional) When `true`, defaults set by Gluu will be respected. Defaults to `false`.
- `backchannel_logout_url` - (Optional) The URL that will cause the client to log itself out when a logout request is sent to this realm. If omitted, no logout request will be sent to the client is this case.
- `backchannel_logout_session_required` - (Optional) When `true`, a sid (session ID) claim will be included in the logout token when the backchannel logout URL is used. Defaults to `true`.
- `backchannel_logout_revoke_offline_sessions` - (Optional) Specifying whether a "revoke_offline_access" event is included in the Logout Token when the Backchannel Logout URL is used. Gluu will revoke offline sessions when receiving a Logout Token with this event.
- `extra_config` - (Optional) A map of key/value pairs to add extra configuration attributes to this client. This can be used for custom attributes, or to add configuration attributes that are not yet supported by this Terraform provider. Use this attribute at your own risk, as it may conflict with top-level configuration attributes in future provider updates.

## Attributes Reference

- `service_account_user_id` - (Computed) When service accounts are enabled for this client, this attribute is the unique ID for the Gluu user that represents this service account.
- `resource_server_id` - (Computed) When authorization is enabled for this client, this attribute is the unique ID for the client (the same value as the `.id` attribute).

## Import

Clients can be imported using the format `{{realm_id}}/{{client_gluu_id}}`, where `client_gluu_id` is the unique ID that Gluu
assigns to the client upon creation. This value can be found in the URI when editing this client in the GUI, and is typically a GUID.

Example:

```bash
terraform import gluu_openid_client.openid_client my-realm/dcbc4c73-e478-4928-ae2e-d5e420223352
```