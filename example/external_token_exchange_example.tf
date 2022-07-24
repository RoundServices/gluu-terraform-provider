resource "gluu_openid_client" "token-exchange_destination_client" {
  name                  = "destination_client"
  client_id             = "destination_client"
  client_secret         = "secret"
  description           = "a client used by the destination"
  access_type           = "CONFIDENTIAL"
  standard_flow_enabled = true
  valid_redirect_uris = [
    "http://localhost:8080/*",
  ]
}

resource gluu_oidc_identity_provider token-exchange_source_oidc_idp {
  alias              = "source"
  authorization_url  = "http://localhost:8080/auth/protocol/openid-connect/auth"
  token_url          = "http://localhost:8080/auth/protocol/openid-connect/token"
  user_info_url      = "http://localhost:8080/auth/protocol/openid-connect/userinfo"
  jwks_url           = "http://localhost:8080/auth/protocol/openid-connect/certs"
  validate_signature = true
  client_id          = gluu_openid_client.token-exchange_destination_client.client_id
  client_secret      = gluu_openid_client.token-exchange_destination_client.client_secret
  default_scopes     = "openid"
}

resource "gluu_openid_client" "token-exchange_webapp_client" {
  name                  = "webapp_client"
  client_id             = "webapp_client"
  client_secret         = "secret"
  description           = "a webapp client on the destination"
  access_type           = "CONFIDENTIAL"
  standard_flow_enabled = true
  valid_redirect_uris = [
    "http://localhost:8080/*",
  ]
}

//token exchange feature enabler
resource "gluu_identity_provider_token_exchange_scope_permission" "source_oidc_idp_permission" {
  provider_alias = gluu_oidc_identity_provider.token-exchange_source_oidc_idp.alias
  policy_type    = "client"
  clients        = [gluu_openid_client.token-exchange_webapp_client.id]
}

