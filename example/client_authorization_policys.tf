resource gluu_openid_client test {
  client_id                = "test-openid-client"
  name                     = "test-openid-client"
  description              = "a test openid client"
  standard_flow_enabled    = true
  service_accounts_enabled = true
  access_type              = "CONFIDENTIAL"
  client_secret            = "secret"
  valid_redirect_uris = [
    "http://localhost:5555/callback",
  ]
  authorization {
    policy_enforcement_mode = "ENFORCING"
  }
}

#
# create aggregate_policy
#

resource gluu_role test_authorization {
  name     = "aggregate_policy_role"
}

resource gluu_openid_client_role_policy test {
  resource_server_id = gluu_openid_client.test.resource_server_id
  name               = "gluu_openid_client_role_policy"
  decision_strategy  = "UNANIMOUS"
  logic              = "POSITIVE"
  type               = "role"
  role {
    id       = gluu_role.test_authorization.id
    required = false
  }
}

resource gluu_openid_client_aggregate_policy test {
  resource_server_id = gluu_openid_client.test.resource_server_id
  name               = "gluu_openid_client_aggregate_policy"
  decision_strategy  = "UNANIMOUS"
  logic              = "POSITIVE"
  policies           = [gluu_openid_client_role_policy.test.id]
}

#
# create client policy
#

resource gluu_openid_client_client_policy test {
  resource_server_id = gluu_openid_client.test.resource_server_id
  name               = "gluu_openid_client_client_policy"
  decision_strategy  = "AFFIRMATIVE"
  logic              = "POSITIVE"
  clients            = [gluu_openid_client.test.resource_server_id]
}

#
# create group policy
#

resource gluu_group test {
  name     = "foo"
}

resource gluu_openid_client_group_policy test {
  resource_server_id = gluu_openid_client.test.resource_server_id
  name               = "client_group_policy_test"
  groups {
    id              = gluu_group.test.id
    path            = gluu_group.test.path
    extend_children = false
  }
  logic             = "POSITIVE"
  decision_strategy = "UNANIMOUS"
}


#
# create JS policy
#

resource gluu_openid_client_js_policy test {
  resource_server_id = gluu_openid_client.test.resource_server_id
  name               = "client_js_policy_test"
  logic              = "POSITIVE"
  decision_strategy  = "UNANIMOUS"
  code               = "test"  # can be js code or a js file already deployed
  description        = "description"
}


#
#  create role policy
#

resource gluu_role test_authorization2 {
  name     = "new_role"
}

resource gluu_openid_client_role_policy test1 {
  resource_server_id = gluu_openid_client.test.resource_server_id
  name               = "gluu_openid_client_role_policy1"
  decision_strategy  = "AFFIRMATIVE"
  logic              = "POSITIVE"
  type               = "role"
  role {
    id       = gluu_role.test_authorization2.id
    required = false
  }
}

#
# create time policy
#

resource gluu_openid_client_time_policy test {
  resource_server_id = gluu_openid_client.test.resource_server_id
  name               = "%s"
  not_on_or_after    = "2500-12-12 01:01:11"
  not_before         = "2400-12-12 01:01:11"
  day_month          = "1"
  day_month_end      = "2"
  year               = "2500"
  year_end           = "2501"
  month              = "1"
  month_end          = "5"
  hour               = "1"
  hour_end           = "5"
  minute             = "10"
  minute_end         = "30"
  logic              = "POSITIVE"
  decision_strategy  = "UNANIMOUS"
}

#
# create user policy
#

resource gluu_user test {
  username = "test-user"

  email      = "test-user@fakedomain.com"
  first_name = "Testy"
  last_name  = "Tester"
}

resource gluu_openid_client_user_policy test {
  resource_server_id = gluu_openid_client.test.resource_server_id
  name               = "client_user_policy_test"
  users              = [gluu_user.test.id]
  logic              = "POSITIVE"
  decision_strategy  = "UNANIMOUS"
}

# users permissions

resource "gluu_users_permissions" "my_permission" {

  view_scope {
    policies          = [
      gluu_openid_client_user_policy.test.id
    ]
    description       = "view_scope"
    decision_strategy = "CONSENSUS"
  }

  manage_scope {
    policies          = [
      gluu_openid_client_user_policy.test.id
    ]
    description       = "manage_scope"
    decision_strategy = "UNANIMOUS"
  }
}

resource "gluu_openid_client_permissions" "my_permission" {
  client_id = gluu_openid_client.test.id

  view_scope {
    policies          = [
      gluu_openid_client_user_policy.test.id,
    ]
    description       = "my description"
    decision_strategy = "UNANIMOUS"
  }
}
