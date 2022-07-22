terraform {
  required_providers {
    gluu = {
      source  = "terraform.local/RoundServices/gluu"
      version = ">= 3.0"
    }
  }
}

provider "gluu" {
  client_id          = "terraform"
  client_secret      = "884e0f95-0f42-4a63-9b1f-94274655669e"
  url                = "http://localhost:8080"
  additional_headers = {
    foo = "bar"
  }
}

resource "gluu_realm" "test" {
  realm             = "test"
  enabled           = true
  display_name      = "foo"
  display_name_html = "<b>foo</b>"

  smtp_server {
    host                  = "mysmtphost.com"
    port                  = 25
    from_display_name     = "Tom"
    from                  = "tom@myhost.com"
    reply_to_display_name = "Tom"
    reply_to              = "tom@myhost.com"
    ssl                   = true
    starttls              = true
    envelope_from         = "nottom@myhost.com"

    auth {
      username = "tom"
      password = "tom"
    }
  }

  account_theme        = "base"
  access_code_lifespan = "30m"

  internationalization {
    supported_locales = [
      "en",
      "de",
      "es",
    ]

    default_locale = "en"
  }

  security_defenses {
    headers {
      x_frame_options                     = "DENY"
      content_security_policy             = "frame-src 'self'; frame-ancestors 'self'; object-src 'none';"
      content_security_policy_report_only = ""
      x_content_type_options              = "nosniff"
      x_robots_tag                        = "none"
      x_xss_protection                    = "1; mode=block"
      strict_transport_security           = "max-age=31536000; includeSubDomains"
    }

    brute_force_detection {
      permanent_lockout                = false
      max_login_failures               = 31
      wait_increment_seconds           = 61
      quick_login_check_milli_seconds  = 1000
      minimum_quick_login_wait_seconds = 120
      max_failure_wait_seconds         = 900
      failure_reset_time_seconds       = 43200
    }
  }

  ssl_required    = "external"
  password_policy = "upperCase(1) and length(8) and forceExpiredPasswordChange(365) and notUsername"

  attributes = {
    mycustomAttribute  = "myCustomValue"
    userProfileEnabled = true
  }

  web_authn_policy {
    relying_party_entity_name = "Example"
    relying_party_id          = "gluu.example.com"
    signature_algorithms      = [
      "ES256",
      "RS256"
    ]
  }

  web_authn_passwordless_policy {
    relying_party_entity_name = "Example"
    relying_party_id          = "gluu.example.com"
    signature_algorithms      = [
      "ES256",
      "RS256"
    ]
  }
}

resource "gluu_required_action" "custom-terms-and-conditions" {
  realm_id       = gluu_realm.test.realm
  alias          = "terms_and_conditions"
  default_action = true
  enabled        = true
  name           = "Custom Terms and Conditions"
}

resource "gluu_required_action" "custom-configured_totp" {
  realm_id       = gluu_realm.test.realm
  alias          = "CONFIGURE_TOTP"
  default_action = true
  enabled        = true
  name           = "Custom configure totp"
  priority       = gluu_required_action.custom-terms-and-conditions.priority + 15
}

resource "gluu_required_action" "required_action" {
  realm_id = gluu_realm.test.realm
  alias    = "webauthn-register"
  enabled  = true
  name     = "Webauthn Register"
}

resource "gluu_group" "foo" {
  realm_id = gluu_realm.test.id
  name     = "foo"
}

resource "gluu_group" "nested_foo" {
  realm_id  = gluu_realm.test.id
  parent_id = gluu_group.foo.id
  name      = "nested-foo"
}

resource "gluu_group" "bar" {
  realm_id = gluu_realm.test.id
  name     = "bar"
}

resource "gluu_user" "user" {
  realm_id = gluu_realm.test.id
  username = "test-user"

  email      = "test-user@fakedomain.com"
  first_name = "Testy"
  last_name  = "Tester"
}

resource "gluu_user" "another_user" {
  realm_id = gluu_realm.test.id
  username = "another-test-user"

  email      = "another-test-user@fakedomain.com"
  first_name = "Testy"
  last_name  = "Tester"
}

resource "gluu_user" "user_with_password" {
  realm_id = gluu_realm.test.id
  username = "user-with-password"

  email      = "user-with-password@fakedomain.com"
  first_name = "Testy"
  last_name  = "Tester"

  initial_password {
    value     = "My password"
    temporary = false
  }
}

resource "gluu_group_memberships" "foo_members" {
  realm_id = gluu_realm.test.id
  group_id = gluu_group.foo.id

  members = [
    gluu_user.user.username,
    gluu_user.another_user.username,
  ]
}

resource "gluu_group" "baz" {
  realm_id = gluu_realm.test.id
  name     = "baz"
}

resource "gluu_default_groups" "default" {
  realm_id  = gluu_realm.test.id
  group_ids = [
    gluu_group.baz.id
  ]
}

resource "gluu_openid_client" "test_client" {
  client_id   = "test-openid-client"
  name        = "test-openid-client"
  realm_id    = gluu_realm.test.id
  description = "a test openid client"

  standard_flow_enabled    = true
  service_accounts_enabled = true

  access_type = "CONFIDENTIAL"

  valid_redirect_uris = [
    "http://localhost:5555/callback",
  ]

  client_secret = "secret"

  pkce_code_challenge_method = "plain"

  login_theme = "gluu"

  backchannel_logout_url                     = "http://localhost:3333/backchannel"
  backchannel_logout_session_required        = true
  backchannel_logout_revoke_offline_sessions = true

  extra_config = {
    customAttribute = "a test custom value"
  }
}

resource "gluu_openid_client_scope" "test_default_client_scope" {
  name     = "test-default-client-scope"
  realm_id = gluu_realm.test.id

  description         = "test"
  consent_screen_text = "hello"
}

resource "gluu_openid_client_scope" "test_optional_client_scope" {
  name     = "test-optional-client-scope"
  realm_id = gluu_realm.test.id

  description         = "test"
  consent_screen_text = "hello"
}

resource "gluu_openid_client_default_scopes" "default_client_scopes" {
  realm_id  = gluu_realm.test.id
  client_id = gluu_openid_client.test_client.id

  default_scopes = [
    "profile",
    "email",
    "roles",
    "web-origins",
    gluu_openid_client_scope.test_default_client_scope.name,
  ]
}

resource "gluu_openid_client_optional_scopes" "optional_client_scopes" {
  realm_id  = gluu_realm.test.id
  client_id = gluu_openid_client.test_client.id

  optional_scopes = [
    "address",
    "phone",
    "offline_access",
    "microprofile-jwt",
    gluu_openid_client_scope.test_optional_client_scope.name,
  ]
}

resource "gluu_ldap_user_federation" "openldap" {
  name     = "openldap"
  realm_id = gluu_realm.test.id

  enabled        = true
  import_enabled = false

  username_ldap_attribute = "cn"
  rdn_ldap_attribute      = "cn"
  uuid_ldap_attribute     = "entryDN"

  user_object_classes = [
    "simpleSecurityObject",
    "organizationalRole",
  ]

  connection_url  = "ldap://openldap"
  users_dn        = "dc=example,dc=org"
  bind_dn         = "cn=admin,dc=example,dc=org"
  bind_credential = "admin"

  connection_timeout = "5s"
  read_timeout       = "10s"

  kerberos {
    server_principal                         = "HTTP/gluu.local@FOO.LOCAL"
    use_kerberos_for_password_authentication = false
    key_tab                                  = "/etc/gluu.keytab"
    kerberos_realm                           = "FOO.LOCAL"
  }

  cache {
    policy = "NO_CACHE"
  }
}

resource "gluu_ldap_role_mapper" "ldap_role_mapper" {
  realm_id                = gluu_realm.test.id
  ldap_user_federation_id = gluu_ldap_user_federation.openldap.id
  name                    = "role-mapper"

  ldap_roles_dn            = "dc=example,dc=org"
  role_name_ldap_attribute = "cn"
  role_object_classes      = [
    "groupOfNames"
  ]
  membership_attribute_type      = "DN"
  membership_ldap_attribute      = "member"
  membership_user_ldap_attribute = "cn"
  user_roles_retrieve_strategy   = "GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE"
  memberof_ldap_attribute        = "memberOf"
}

resource "gluu_ldap_user_attribute_mapper" "description_attr_mapper" {
  name                    = "description-mapper"
  realm_id                = gluu_ldap_user_federation.openldap.realm_id
  ldap_user_federation_id = gluu_ldap_user_federation.openldap.id

  user_model_attribute = "description"
  ldap_attribute       = "description"

  always_read_value_from_ldap = false
}

resource "gluu_ldap_group_mapper" "group_mapper" {
  name                    = "group mapper"
  realm_id                = gluu_ldap_user_federation.openldap.realm_id
  ldap_user_federation_id = gluu_ldap_user_federation.openldap.id

  ldap_groups_dn            = "dc=example,dc=org"
  group_name_ldap_attribute = "cn"

  group_object_classes = [
    "groupOfNames",
  ]

  membership_attribute_type      = "DN"
  membership_ldap_attribute      = "member"
  membership_user_ldap_attribute = "cn"
  memberof_ldap_attribute        = "memberOf"
}

resource "gluu_ldap_msad_user_account_control_mapper" "msad_uac_mapper" {
  name                    = "uac-mapper1"
  realm_id                = gluu_ldap_user_federation.openldap.realm_id
  ldap_user_federation_id = gluu_ldap_user_federation.openldap.id
}

resource "gluu_ldap_msad_lds_user_account_control_mapper" "msad_lds_uac_mapper" {
  name                    = "msad-lds-uac-mapper"
  realm_id                = gluu_ldap_user_federation.openldap.realm_id
  ldap_user_federation_id = gluu_ldap_user_federation.openldap.id
}

resource "gluu_ldap_full_name_mapper" "full_name_mapper" {
  name                    = "full-name-mapper"
  realm_id                = gluu_ldap_user_federation.openldap.realm_id
  ldap_user_federation_id = gluu_ldap_user_federation.openldap.id

  ldap_full_name_attribute = "cn"
  read_only                = true
}

resource "gluu_custom_user_federation" "custom" {
  name        = "custom1"
  realm_id    = "master"
  provider_id = "custom"

  enabled = true
}

resource "gluu_openid_user_attribute_protocol_mapper" "map_user_attributes_client" {
  name           = "tf-test-open-id-user-attribute-protocol-mapper-client"
  realm_id       = gluu_realm.test.id
  client_id      = gluu_openid_client.test_client.id
  user_attribute = "description"
  claim_name     = "description"
}

resource "gluu_openid_user_attribute_protocol_mapper" "map_user_permissions_attributes_client" {
  name           = "tf-test-open-id-user-multivalue-attribute-protocol-mapper-client"
  realm_id       = gluu_realm.test.id
  client_id      = gluu_openid_client.test_client.id
  user_attribute = "permissions"
  claim_name     = "permissions"
  multivalued    = true
}


resource "gluu_openid_user_attribute_protocol_mapper" "map_user_attributes_client_scope" {
  name            = "tf-test-open-id-user-attribute-protocol-mapper-client-scope"
  realm_id        = gluu_realm.test.id
  client_scope_id = gluu_openid_client_scope.test_default_client_scope.id
  user_attribute  = "foo2"
  claim_name      = "bar2"
}

resource "gluu_openid_group_membership_protocol_mapper" "map_group_memberships_client" {
  name       = "tf-test-open-id-group-membership-protocol-mapper-client"
  realm_id   = gluu_realm.test.id
  client_id  = gluu_openid_client.test_client.id
  claim_name = "bar"
}

resource "gluu_openid_group_membership_protocol_mapper" "map_group_memberships_client_scope" {
  name            = "tf-test-open-id-group-membership-protocol-mapper-client-scope"
  realm_id        = gluu_realm.test.id
  client_scope_id = gluu_openid_client_scope.test_optional_client_scope.id
  claim_name      = "bar2"
}

resource "gluu_openid_full_name_protocol_mapper" "map_full_names_client" {
  name      = "tf-test-open-id-full-name-protocol-mapper-client"
  realm_id  = gluu_realm.test.id
  client_id = gluu_openid_client.test_client.id
}

resource "gluu_openid_full_name_protocol_mapper" "map_full_names_client_scope" {
  name            = "tf-test-open-id-full-name-protocol-mapper-client-scope"
  realm_id        = gluu_realm.test.id
  client_scope_id = gluu_openid_client_scope.test_default_client_scope.id
}

resource "gluu_openid_user_property_protocol_mapper" "map_user_properties_client" {
  name          = "tf-test-open-id-user-property-protocol-mapper-client"
  realm_id      = gluu_realm.test.id
  client_id     = gluu_openid_client.test_client.id
  user_property = "foo"
  claim_name    = "bar"
}

resource "gluu_openid_user_property_protocol_mapper" "map_user_properties_client_scope" {
  name            = "tf-test-open-id-user-property-protocol-mapper-client-scope"
  realm_id        = gluu_realm.test.id
  client_scope_id = gluu_openid_client_scope.test_optional_client_scope.id
  user_property   = "foo2"
  claim_name      = "bar2"
}

resource "gluu_openid_hardcoded_claim_protocol_mapper" "hardcoded_claim_client" {
  name      = "tf-test-open-id-hardcoded-claim-protocol-mapper-client"
  realm_id  = gluu_realm.test.id
  client_id = gluu_openid_client.test_client.id

  claim_name  = "foo"
  claim_value = "bar"
}

resource "gluu_openid_hardcoded_claim_protocol_mapper" "hardcoded_claim_client_scope" {
  name            = "tf-test-open-id-hardcoded-claim-protocol-mapper-client-scope"
  realm_id        = gluu_realm.test.id
  client_scope_id = gluu_openid_client_scope.test_default_client_scope.id

  claim_name  = "foo"
  claim_value = "bar"
}

resource "gluu_openid_user_realm_role_protocol_mapper" "user_realm_role_client" {
  name      = "tf-test-open-id-user-realm-role-claim-protocol-mapper-client"
  realm_id  = gluu_realm.test.id
  client_id = gluu_openid_client.test_client.id

  claim_name = "foo"
}

resource "gluu_openid_user_realm_role_protocol_mapper" "user_realm_role_client_scope" {
  name            = "tf-test-open-id-user-realm-role-protocol-mapper-client-scope"
  realm_id        = gluu_realm.test.id
  client_scope_id = gluu_openid_client_scope.test_default_client_scope.id

  claim_name = "foo"
}

resource "gluu_openid_user_client_role_protocol_mapper" "user_client_role_client" {
  name      = "tf-test-open-id-user-client-role-claim-protocol-mapper-client"
  realm_id  = gluu_realm.test.id
  client_id = gluu_openid_client.test_client.id

  claim_name  = "foo"
  multivalued = false

  client_id_for_role_mappings = gluu_openid_client.bearer_only_client.client_id
  client_role_prefix          = "prefixValue"

  add_to_id_token     = true
  add_to_access_token = false
  add_to_userinfo     = false
}

resource "gluu_openid_user_client_role_protocol_mapper" "user_client_role_client_scope" {
  name            = "tf-test-open-id-user-client-role-protocol-mapper-client-scope"
  realm_id        = gluu_realm.test.id
  client_scope_id = gluu_openid_client_scope.test_default_client_scope.id

  claim_name  = "foo"
  multivalued = false

  client_id_for_role_mappings = gluu_openid_client.bearer_only_client.client_id
  client_role_prefix          = "prefixValue"

  add_to_id_token     = true
  add_to_access_token = false
  add_to_userinfo     = false
}

resource "gluu_openid_user_session_note_protocol_mapper" "user_session_note_client" {
  name      = "tf-test-open-id-user-session-note-protocol-mapper-client"
  realm_id  = gluu_realm.test.id
  client_id = gluu_openid_client.test_client.id

  claim_name       = "foo"
  claim_value_type = "String"
  session_note     = "bar"

  add_to_id_token     = true
  add_to_access_token = false
}

resource "gluu_openid_user_session_note_protocol_mapper" "user_session_note_client_scope" {
  name            = "tf-test-open-id-user-session-note-protocol-mapper-client-scope"
  realm_id        = gluu_realm.test.id
  client_scope_id = gluu_openid_client_scope.test_default_client_scope.id

  claim_name       = "foo2"
  claim_value_type = "String"
  session_note     = "bar2"

  add_to_id_token     = true
  add_to_access_token = false
}

resource "gluu_openid_client" "bearer_only_client" {
  client_id   = "test-bearer-only-client"
  name        = "test-bearer-only-client"
  realm_id    = gluu_realm.test.id
  description = "a test openid client using bearer-only"

  access_type = "BEARER-ONLY"
}

resource "gluu_openid_audience_protocol_mapper" "audience_client_scope" {
  name            = "tf-test-openid-audience-protocol-mapper-client-scope"
  realm_id        = gluu_realm.test.id
  client_scope_id = gluu_openid_client_scope.test_default_client_scope.id

  add_to_id_token     = true
  add_to_access_token = false

  included_client_audience = gluu_openid_client.bearer_only_client.client_id
}

resource "gluu_openid_audience_protocol_mapper" "audience_client" {
  name      = "tf-test-openid-audience-protocol-mapper-client"
  realm_id  = gluu_realm.test.id
  client_id = gluu_openid_client.test_client.id

  add_to_id_token     = false
  add_to_access_token = true

  included_custom_audience = "foo"
}

resource gluu_oidc_identity_provider oidc {
  realm             = gluu_realm.test.id
  alias             = "oidc"
  authorization_url = "https://example.com/auth"
  token_url         = "https://example.com/token"
  client_id         = "example_id"
  client_secret     = "example_token"
  default_scopes    = "openid random profile"
  sync_mode         = "FORCE"
  gui_order         = 1
}

resource gluu_oidc_google_identity_provider google {
  realm                                   = gluu_realm.test.id
  client_id                               = "myclientid.apps.googleusercontent.com"
  client_secret                           = "myclientsecret"
  hosted_domain                           = "mycompany.com"
  request_refresh_token                   = true
  default_scopes                          = "openid random profile"
  accepts_prompt_none_forward_from_client = false
  sync_mode                               = "FORCE"
  gui_order                               = 2
}

//This example does not work in gluu 10, because the interfaces that our customIdp implements, have changed in the gluu latest version.
//We need to make decide which gluu version we going to support and test for the customIdp
//resource gluu_oidc_identity_provider custom_oidc_idp {
//  realm             = "${gluu_realm.test.id}"
//  provider_id       = "customIdp"
//  alias             = "custom"
//  authorization_url = "https://example.com/auth"
//  token_url         = "https://example.com/token"
//  client_id         = "example_id"
//  client_secret     = "example_token"
//
//  extra_config = {
//    dummyConfig = "dummyValue"
//  }
//}

resource gluu_attribute_importer_identity_provider_mapper oidc {
  realm                   = gluu_realm.test.id
  name                    = "attributeImporter"
  claim_name              = "upn"
  identity_provider_alias = gluu_oidc_identity_provider.oidc.alias
  user_attribute          = "email"

  #KC10 support
  extra_config = {
    syncMode = "INHERIT"
  }
}

resource gluu_attribute_to_role_identity_provider_mapper oidc {
  realm                   = gluu_realm.test.id
  name                    = "attributeToRole"
  claim_name              = "upn"
  identity_provider_alias = gluu_oidc_identity_provider.oidc.alias
  claim_value             = "value"
  role                    = "testRole"

  #KC10 support
  extra_config = {
    syncMode = "INHERIT"
  }
}

resource gluu_user_template_importer_identity_provider_mapper oidc {
  realm                   = gluu_realm.test.id
  name                    = "userTemplate"
  identity_provider_alias = gluu_oidc_identity_provider.oidc.alias
  template                = "$${ALIAS}/$${CLAIM.upn}"

  #KC10 support
  extra_config = {
    syncMode = "INHERIT"
  }
}

resource gluu_hardcoded_role_identity_provider_mapper oidc {
  realm                   = gluu_realm.test.id
  name                    = "hardcodedRole"
  identity_provider_alias = gluu_oidc_identity_provider.oidc.alias
  role                    = "testrole"

  #KC10 support
  extra_config = {
    syncMode = "INHERIT"
  }
}

resource gluu_hardcoded_attribute_identity_provider_mapper oidc {
  realm                   = gluu_realm.test.id
  name                    = "hardcodedUserSessionAttribute"
  identity_provider_alias = gluu_oidc_identity_provider.oidc.alias
  attribute_name          = "attribute"
  attribute_value         = "value"
  user_session            = true

  #KC10 support
  extra_config = {
    syncMode = "INHERIT"
  }
}

data "gluu_openid_client" "broker" {
  realm_id  = gluu_realm.test.id
  client_id = "broker"
}

data "gluu_openid_client_authorization_policy" "default" {
  realm_id           = gluu_realm.test.id
  resource_server_id = gluu_openid_client.test_client_auth.resource_server_id
  name               = "default"
}

resource "gluu_openid_client" "test_client_auth" {
  client_id   = "test-client-auth"
  name        = "test-client-auth"
  realm_id    = gluu_realm.test.id
  description = "a test openid client"

  access_type                  = "CONFIDENTIAL"
  direct_access_grants_enabled = true
  implicit_flow_enabled        = true
  service_accounts_enabled     = true

  valid_redirect_uris = [
    "http://localhost:5555/callback",
  ]

  authorization {
    policy_enforcement_mode = "ENFORCING"
  }

  client_secret = "secret"
}

resource gluu_openid_client test_open_id_client_with_consent_text {
  client_id   = "test_open_id_client_with_consent_text"
  name        = "test_open_id_client_with_consent_text"
  realm_id    = gluu_realm.test.id
  description = "a test openid client that has consent text"

  standard_flow_enabled    = true
  service_accounts_enabled = true

  access_type = "CONFIDENTIAL"

  valid_redirect_uris = [
    "http://localhost:5555/callback",
  ]

  client_secret = "secret"

  pkce_code_challenge_method = "plain"

  login_theme = "gluu"

  backchannel_logout_url                     = "http://localhost:3333/backchannel"
  backchannel_logout_session_required        = true
  backchannel_logout_revoke_offline_sessions = true

  extra_config = {
    customAttribute = "a test custom value"
  }

  consent_required          = true
  display_on_consent_screen = true
  consent_screen_text       = "some consent screen text"
}


resource "gluu_openid_client_authorization_permission" "resource" {
  resource_server_id = gluu_openid_client.test_client_auth.resource_server_id
  realm_id           = gluu_realm.test.id
  name               = "test"

  policies = [
    data.gluu_openid_client_authorization_policy.default.id,
  ]

  resources = [
    gluu_openid_client_authorization_resource.resource.id,
  ]

  scopes = [
    gluu_openid_client_authorization_scope.resource.id
  ]
}

resource "gluu_openid_client_authorization_resource" "resource" {
  resource_server_id = gluu_openid_client.test_client_auth.resource_server_id
  name               = "test-openid-client1"
  realm_id           = gluu_realm.test.id

  uris = [
    "/endpoint/*",
  ]

  attributes = {
    "asdads" = "asdasd"
  }
}

resource "gluu_openid_client_authorization_scope" "resource" {
  resource_server_id = gluu_openid_client.test_client_auth.resource_server_id
  name               = "test-openid-client1"
  realm_id           = gluu_realm.test.id
}

resource "gluu_user" "user_with_multivalueattributes" {
  realm_id = gluu_realm.test.id
  username = "user-with-mutivalueattributes"

  attributes = {
    "permissions" = "permission1##permission2"
  }
  initial_password {
    value     = "My password"
    temporary = false
  }
}

resource "gluu_user" "resource" {
  realm_id = gluu_realm.test.id
  username = "test"

  attributes = {
    "key" = "value"
  }
}

resource "gluu_openid_client_service_account_role" "read_token" {
  realm_id                = gluu_realm.test.id
  client_id               = data.gluu_openid_client.broker.id
  service_account_user_id = gluu_openid_client.test_client_auth.service_account_user_id
  role                    = "read-token"
}

resource "gluu_authentication_flow" "browser-copy-flow" {
  alias       = "browserCopyFlow"
  realm_id    = gluu_realm.test.id
  description = "browser based authentication"
}

resource "gluu_authentication_execution" "browser-copy-cookie" {
  realm_id          = gluu_realm.test.id
  parent_flow_alias = gluu_authentication_flow.browser-copy-flow.alias
  authenticator     = "auth-cookie"
  requirement       = "ALTERNATIVE"
  depends_on        = [
    gluu_authentication_execution.browser-copy-kerberos
  ]
}

resource "gluu_authentication_execution" "browser-copy-kerberos" {
  realm_id          = gluu_realm.test.id
  parent_flow_alias = gluu_authentication_flow.browser-copy-flow.alias
  authenticator     = "auth-spnego"
  requirement       = "DISABLED"
}

resource "gluu_authentication_execution" "browser-copy-idp-redirect" {
  realm_id          = gluu_realm.test.id
  parent_flow_alias = gluu_authentication_flow.browser-copy-flow.alias
  authenticator     = "identity-provider-redirector"
  requirement       = "ALTERNATIVE"
  depends_on        = [
    gluu_authentication_execution.browser-copy-cookie
  ]
}

resource "gluu_authentication_subflow" "browser-copy-flow-forms" {
  realm_id          = gluu_realm.test.id
  parent_flow_alias = gluu_authentication_flow.browser-copy-flow.alias
  alias             = "browser-copy-flow-forms"
  requirement       = "ALTERNATIVE"
  depends_on        = [
    gluu_authentication_execution.browser-copy-idp-redirect
  ]
}

resource "gluu_authentication_execution" "browser-copy-auth-username-password-form" {
  realm_id          = gluu_realm.test.id
  parent_flow_alias = gluu_authentication_subflow.browser-copy-flow-forms.alias
  authenticator     = "auth-username-password-form"
  requirement       = "REQUIRED"
}

resource "gluu_authentication_execution" "browser-copy-otp" {
  realm_id          = gluu_realm.test.id
  parent_flow_alias = gluu_authentication_subflow.browser-copy-flow-forms.alias
  authenticator     = "auth-otp-form"
  requirement       = "REQUIRED"
  depends_on        = [
    gluu_authentication_execution.browser-copy-auth-username-password-form
  ]
}

resource "gluu_authentication_execution_config" "config" {
  realm_id     = gluu_realm.test.id
  execution_id = gluu_authentication_execution.browser-copy-idp-redirect.id
  alias        = "idp-XXX-config"
  config       = {
    defaultProvider = "idp-XXX"
  }
}

resource "gluu_authentication_bindings" "test_bindings" {
  realm_id     = gluu_realm.test.id
  browser_flow = gluu_authentication_flow.browser-copy-flow.alias
}

resource "gluu_openid_client" "client" {
  client_id   = "my-override-flow-binding-client"
  realm_id    = gluu_realm.test.id
  access_type = "PUBLIC"
  authentication_flow_binding_overrides {
    browser_id = gluu_authentication_flow.browser-copy-flow.id
  }
}

resource "gluu_realm_user_profile" "userprofile" {
  realm_id = gluu_realm.test.id

  attribute {
    name         = "field1"
    display_name = "Field 1"
    group        = "group1"

    enabled_when_scope = ["offline_access"]

    required_for_roles  = ["user"]
    required_for_scopes = ["offline_access"]

    permissions {
      view = ["admin", "user"]
      edit = ["admin", "user"]
    }

    validator {
      name = "person-name-prohibited-characters"
    }

    validator {
      name   = "pattern"
      config = {
        pattern       = "^[a-z]+$"
        error_message = "Nope"
      }
    }

    annotations = {
      foo = "bar"
    }
  }

  attribute {
    name = "field2"
  }

  group {
    name                = "group1"
    display_header      = "Group 1"
    display_description = "A first group"

    annotations = {
      foo = "bar"
    }
  }

  group {
    name = "group2"
  }
}
