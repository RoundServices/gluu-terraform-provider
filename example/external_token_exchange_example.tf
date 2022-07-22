resource "gluu_realm" "token-exchange_source_realm" {
  realm   = "token-exchange_source_realm"
  enabled = true
}

resource "gluu_openid_client" "token-exchange_destination_client" {
  realm_id              = gluu_realm.token-exchange_source_realm.id
  name                  = "destination_client"
  client_id             = "destination_client"
  client_secret         = "secret"
  description           = "a client used by the destination realm"
  access_type           = "CONFIDENTIAL"
  standard_flow_enabled = true
  valid_redirect_uris = [
    "http://localhost:8080/*",
  ]
}

resource "gluu_realm" "token-exchange_destination_realm" {
  realm   = "token-exchange_destination_realm"
  enabled = true
}

resource gluu_oidc_identity_provider token-exchange_source_oidc_idp {
  realm              = gluu_realm.token-exchange_destination_realm.id
  alias              = "source"
  authorization_url  = "http://localhost:8080/auth/realms/${gluu_realm.token-exchange_source_realm.id}/protocol/openid-connect/auth"
  token_url          = "http://localhost:8080/auth/realms/${gluu_realm.token-exchange_source_realm.id}/protocol/openid-connect/token"
  user_info_url      = "http://localhost:8080/auth/realms/${gluu_realm.token-exchange_source_realm.id}/protocol/openid-connect/userinfo"
  jwks_url           = "http://localhost:8080/auth/realms/${gluu_realm.token-exchange_source_realm.id}/protocol/openid-connect/certs"
  validate_signature = true
  client_id          = gluu_openid_client.token-exchange_destination_client.client_id
  client_secret      = gluu_openid_client.token-exchange_destination_client.client_secret
  default_scopes     = "openid"
}

resource "gluu_openid_client" "token-exchange_webapp_client" {
  realm_id              = gluu_realm.token-exchange_destination_realm.id
  name                  = "webapp_client"
  client_id             = "webapp_client"
  client_secret         = "secret"
  description           = "a webapp client on the destination realm"
  access_type           = "CONFIDENTIAL"
  standard_flow_enabled = true
  valid_redirect_uris = [
    "http://localhost:8080/*",
  ]
}

//token exchange feature enabler
resource "gluu_identity_provider_token_exchange_scope_permission" "source_oidc_idp_permission" {
  realm_id       = gluu_realm.token-exchange_destination_realm.id
  provider_alias = gluu_oidc_identity_provider.token-exchange_source_oidc_idp.alias
  policy_type    = "client"
  clients        = [gluu_openid_client.token-exchange_webapp_client.id]
}

