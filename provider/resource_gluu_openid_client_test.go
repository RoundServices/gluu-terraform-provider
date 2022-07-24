package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/RoundServices/gluu-terraform-provider/gluu"
)

type GluuBoolQuoted bool

func TestAccGluuOpenidClient_basic(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_basic(clientId),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     "/",
				ImportStateVerifyIgnore: []string{"exclude_session_state_from_auth_response"},
			},
		},
	})
}

func TestAccGluuOpenidClient_basic_with_consent(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_basic_with_consent(clientId),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     "/",
				ImportStateVerifyIgnore: []string{"exclude_session_state_from_auth_response"},
			},
		},
	})
}

func TestAccGluuOpenidClient_createAfterManualDestroy(t *testing.T) {
	t.Parallel()
	var client = &gluu.OpenidClient{}

	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_basic(clientId),
				Check: resource.ComposeTestCheckFunc(
				),
			},
			{
				PreConfig: func() {
					err := gluuClient.DeleteOpenidClient(testCtx, client)
					if err != nil {
						t.Fatal(err)
					}
				},
				Config: testGluuOpenidClient_basic(clientId),
			},
		},
	})
}

func TestAccGluuOpenidClient(t *testing.T) {
	t.Parallel()

	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient(clientId),
				Check: resource.ComposeTestCheckFunc(
				),
			},
		},
	})
}

func TestAccGluuOpenidClient_updateInPlace(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	openidClientBefore := &gluu.OpenidClient{
		Inum:                  clientId,
		DisplayName:           acctest.RandString(10),
		ClientSecret:          acctest.RandString(10),
		RedirectUris:         []string{acctest.RandString(10), acctest.RandString(10), acctest.RandString(10), acctest.RandString(10)},
	}

	openidClientAfter := &gluu.OpenidClient{
		Inum:                  clientId,
		DisplayName:           acctest.RandString(10),
		ClientSecret:          acctest.RandString(10),
		RedirectUris:         []string{acctest.RandString(10), acctest.RandString(10)},
	}

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_fromInterface(openidClientBefore),
				Check: resource.ComposeTestCheckFunc(
				),
			},
			{
				Config: testGluuOpenidClient_fromInterface(openidClientAfter),
				Check: resource.ComposeTestCheckFunc(
				),
			},
			{
				Config: testGluuOpenidClient_basic(clientId),
				Check: resource.ComposeTestCheckFunc(
				),
			},
		},
	})
}

func TestAccGluuOpenidClient_backChannel(t *testing.T) {
	t.Parallel()

	clientId := acctest.RandomWithPrefix("tf-acc")
	backchannelLogoutUrl := fmt.Sprintf("https://%s.com", acctest.RandString(10))
	backchannelLogoutSessionRequired := randomBool()
	backchannelLogoutRevokeOfflineSessions := !backchannelLogoutSessionRequired

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_backchannel(clientId, backchannelLogoutUrl, backchannelLogoutSessionRequired, backchannelLogoutRevokeOfflineSessions),
				Check: resource.ComposeTestCheckFunc(
				),
			},
		},
	})
}

func TestAccGluuOpenidClient_frontChannel(t *testing.T) {
	t.Parallel()

	clientId := acctest.RandomWithPrefix("tf-acc")
	frontchannelLogoutUrl := fmt.Sprintf("https://%s.com/logout", acctest.RandString(10))
	frontchannelLogoutEnabled := true

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_frontchannel(clientId, frontchannelLogoutUrl, frontchannelLogoutEnabled),
				Check: resource.ComposeTestCheckFunc(
				),
			},
		},
	})
}

func TestAccGluuOpenidClient_AccessToken_basic(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	accessTokenLifespan := "1800"

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_AccessToken_basic(clientId, accessTokenLifespan),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     "/",
				ImportStateVerifyIgnore: []string{"exclude_session_state_from_auth_response"},
			},
		},
	})
}

func TestAccGluuOpenidClient_ClientTimeouts_basic(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	offlineSessionIdleTimeout := "1800"
	offlineSessionMaxLifespan := "1900"
	sessionIdleTimeout := "2000"
	sessionMaxLifespan := "2100"

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_ClientTimeouts(clientId,
					offlineSessionIdleTimeout, offlineSessionMaxLifespan, sessionIdleTimeout, sessionMaxLifespan),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     "/",
				ImportStateVerifyIgnore: []string{"exclude_session_state_from_auth_response"},
			},
		},
	})
}

func TestAccGluuOpenidClient_Device_basic(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	oauth2DeviceCodeLifespan := "300"
	oauth2DevicePollingInterval := "60"
	oauth2DeviceAuthorizationGrantEnabled := true

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_oauth2DeviceTimes(clientId,
					oauth2DeviceCodeLifespan, oauth2DevicePollingInterval, oauth2DeviceAuthorizationGrantEnabled,
				),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     "/",
				ImportStateVerifyIgnore: []string{"exclude_session_state_from_auth_response"},
			},
		},
	})
}

func TestAccGluuOpenidClient_secret(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")
	clientSecret := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_basic(clientId),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasNonEmptyClientSecret("gluu_openid_client.client"),
				),
			},
			{
				Config: testGluuOpenidClient_secret(clientId, clientSecret),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasClientSecret("gluu_openid_client.client", clientSecret),
				),
			},
		},
	})
}

func TestAccGluuOpenidClient_redirectUrisValidation(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")
	accessType := randomStringInSlice([]string{"PUBLIC", "CONFIDENTIAL"})

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config:      testGluuOpenidClient_invalidRedirectUris(clientId, accessType, true, false),
				ExpectError: regexp.MustCompile("validation error: standard \\(authorization code\\) and implicit flows require at least one valid redirect uri"),
			},
			{
				Config:      testGluuOpenidClient_invalidRedirectUris(clientId, accessType, false, true),
				ExpectError: regexp.MustCompile("validation error: standard \\(authorization code\\) and implicit flows require at least one valid redirect uri"),
			},
		},
	})
}

func TestAccGluuOpenidClient_publicClientCredentialsValidation(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config:      testGluuOpenidClient_invalidPublicClientWithClientCredentials(clientId),
				ExpectError: regexp.MustCompile("validation error: service accounts \\(client credentials flow\\) cannot be enabled on public clients"),
			},
		},
	})
}

func TestAccGluuOpenidClient_bearerClientNoGrantsValidation(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config:      testGluuOpenidClient_bearerOnlyClientsCannotIssueTokens(clientId, true, false, false, false),
				ExpectError: regexp.MustCompile("validation error: Gluu cannot issue tokens for bearer-only clients; no oauth2 flows can be enabled for this client"),
			},
			{
				Config:      testGluuOpenidClient_bearerOnlyClientsCannotIssueTokens(clientId, false, true, false, false),
				ExpectError: regexp.MustCompile("validation error: Gluu cannot issue tokens for bearer-only clients; no oauth2 flows can be enabled for this client"),
			},
			{
				Config:      testGluuOpenidClient_bearerOnlyClientsCannotIssueTokens(clientId, false, false, true, false),
				ExpectError: regexp.MustCompile("validation error: Gluu cannot issue tokens for bearer-only clients; no oauth2 flows can be enabled for this client"),
			},
			{
				Config:      testGluuOpenidClient_bearerOnlyClientsCannotIssueTokens(clientId, false, false, false, true),
				ExpectError: regexp.MustCompile("validation error: Gluu cannot issue tokens for bearer-only clients; no oauth2 flows can be enabled for this client"),
			},
		},
	})
}


func testAccCheckGluuOpenidClientFetch(resourceName string, client *gluu.OpenidClient) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		fetchedClient, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		client.Id = fetchedClient.Id

		return nil
	}
}


func testAccCheckGluuOpenidClientHasClientSecret(resourceName, secret string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.ClientSecret != secret {
			return fmt.Errorf("expected openid client %s to have secret value of %s, but got %s", client.Inum, secret, client.ClientSecret)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientHasNonEmptyClientSecret(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.ClientSecret == "" {
			return fmt.Errorf("expected openid client %s to have non empty secret value", client.Inum)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientDestroy() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for _, rs := range s.RootModule().Resources {
			if rs.Type != "gluu_openid_client" {
				continue
			}

			id := rs.Primary.ID

			client, _ := gluuClient.GetOpenidClient(testCtx, id)
			if client != nil {
				return fmt.Errorf("openid client %s still exists", id)
			}
		}

		return nil
	}
}

func getOpenidClientFromState(s *terraform.State, resourceName string) (*gluu.OpenidClient, error) {
	rs, ok := s.RootModule().Resources[resourceName]
	if !ok {
		return nil, fmt.Errorf("resource not found: %s", resourceName)
	}

	id := rs.Primary.ID

	client, err := gluuClient.GetOpenidClient(testCtx, id)
	if err != nil {
		return nil, fmt.Errorf("error getting openid client %s: %s", id, err)
	}

	return client, nil
}

func testGluuOpenidClient_basic(clientId string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"
}
	`, clientId)
}

func testGluuOpenidClient_basic_with_consent(clientId string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   				= "%s"
	access_type 				= "CONFIDENTIAL"
	consent_required            = true
	display_on_consent_screen	= true
	consent_screen_text         = "some consent screen text"
}
	`, clientId)
}

func testGluuOpenidClient_AccessToken_basic(clientId, accessTokenLifespan string) string {
	return fmt.Sprintf(`
esource "gluu_openid_client" "client" {
	client_id   		  = "%s"
	access_type 		  = "CONFIDENTIAL"
	access_token_lifespan = "%s"
}
	`, clientId, accessTokenLifespan)
}

func testGluuOpenidClient_ClientTimeouts(clientId,
	offlineSessionIdleTimeout string, offlineSessionMaxLifespan string,
	sessionIdleTimeout string, sessionMaxLifespan string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   		  = "%s"
	access_type 		  = "CONFIDENTIAL"

	client_offline_session_idle_timeout = "%s"
	client_offline_session_max_lifespan = "%s"
	client_session_idle_timeout         = "%s"
	client_session_max_lifespan         = "%s"
}
	`, clientId, offlineSessionIdleTimeout, offlineSessionMaxLifespan, sessionIdleTimeout, sessionMaxLifespan)
}

func testGluuOpenidClient_accessType(clientId, accessType string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "%s"
}
	`, clientId, accessType)
}

func testGluuOpenidClient_clientAuthenticatorType(clientId, authType string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id                 = "%s"
	access_type               = "CONFIDENTIAL"
	client_authenticator_type = "%s"
}
	`, clientId, authType)
}

func testGluuOpenidClient_pkceChallengeMethod(clientId, pkceChallengeMethod string) string {

	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"
	pkce_code_challenge_method = "%s"
}
	`, clientId, pkceChallengeMethod)
}

func testGluuOpenidClient_excludeSessionStateFromAuthResponse(clientId string, excludeSessionStateFromAuthResponse bool) string {

	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"
	exclude_session_state_from_auth_response = %t
}
	`, clientId, excludeSessionStateFromAuthResponse)
}

func testGluuOpenidClient_omitPkceChallengeMethod(clientId string) string {

	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"
}
	`, clientId)
}

func testGluuOpenidClient_omitExcludeSessionStateFromAuthResponse(clientId, pkceChallengeMethod string) string {

	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"
    pkce_code_challenge_method = "%s"
}
	`, clientId, pkceChallengeMethod)
}

func testGluuOpenidClient(clientId string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "BEARER-ONLY"
}
	`, clientId)
}

func testGluuOpenidClient_fromInterface(openidClient *gluu.OpenidClient) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	inum                    = "%s"
	displayName             = "%s"
	client_secret           = "%s"
	redirect_uris           = %s
}
	`, openidClient.Inum, openidClient.DisplayName, openidClient.ClientSecret, arrayOfStringsForTerraformResource(openidClient.RedirectUris))
}

func testGluuOpenidClient_backchannel(clientId, backchannelLogoutUrl string, backchannelLogoutSessionRequired, backchannelLogoutRevokeOfflineSessions bool) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"

	backchannel_logout_url                     = "%s"
	backchannel_logout_session_required        = %t
	backchannel_logout_revoke_offline_sessions = %t
}
	`, clientId, backchannelLogoutUrl, backchannelLogoutSessionRequired, backchannelLogoutRevokeOfflineSessions)
}

func testGluuOpenidClient_frontchannel(clientId, frontchannelLogoutUrl string, frontchannelLogoutEnabled bool) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"

	frontchannel_logout_url     = "%s"
	frontchannel_logout_enabled = %t
}
	`, clientId, frontchannelLogoutUrl, frontchannelLogoutEnabled)
}

func testGluuOpenidClient_secret(clientId, clientSecret string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id     = "%s"
	access_type   = "CONFIDENTIAL"
	client_secret = "%s"
}
	`, clientId, clientSecret)
}

func testGluuOpenidClient_invalidRedirectUris(clientId, accessType string, standardFlowEnabled, implicitFlowEnabled bool) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id             = "%s"
	access_type           = "%s"

	standard_flow_enabled = %t
	implicit_flow_enabled = %t
}
	`, clientId, accessType, standardFlowEnabled, implicitFlowEnabled)
}

func testGluuOpenidClient_invalidPublicClientWithClientCredentials(clientId string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id                = "%s"
	access_type              = "PUBLIC"

	service_accounts_enabled = true
}
	`, clientId)
}

func testGluuOpenidClient_bearerOnlyClientsCannotIssueTokens(clientId string, standardFlowEnabled, implicitFlowEnabled, directAccessGrantsEnabled, serviceAccountsEnabled bool) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id                    = "%s"
	access_type                  = "BEARER-ONLY"

	standard_flow_enabled        = %t
	implicit_flow_enabled        = %t
	direct_access_grants_enabled = %t
	service_accounts_enabled     = %t
}
	`, clientId, standardFlowEnabled, implicitFlowEnabled, directAccessGrantsEnabled, serviceAccountsEnabled)
}

func testGluuOpenidClient_authenticationFlowBindingOverrides(clientId string) string {
	return fmt.Sprintf(`
resource "gluu_authentication_flow" "another_flow" {
  alias    = "anotherFlow"
  description = "this is another flow"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "PUBLIC"
	authentication_flow_binding_overrides {
		browser_id = "${gluu_authentication_flow.another_flow.id}"
		direct_grant_id = "${gluu_authentication_flow.another_flow.id}"
	}
}
	`, clientId)
}

func testGluuOpenidClient_withoutAuthenticationFlowBindingOverrides(clientId string) string {
	return fmt.Sprintf(`
resource "gluu_authentication_flow" "another_flow" {
  alias    = "anotherFlow"
  description = "this is another flow"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "PUBLIC"
}
	`, clientId)
}

func testGluuOpenidClient_loginTheme(clientId, loginTheme string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "PUBLIC"
	login_theme = "%s"
}
	`, clientId, loginTheme)
}

func testGluuOpenidClient_useRefreshTokens(clientId string, useRefreshTokens bool) string {

	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"
	use_refresh_tokens = %t
}
	`, clientId, useRefreshTokens)
}

func testGluuOpenidClient_useRefreshTokensClientCredentials(clientId string, useRefreshTokensClientCredentials bool) string {

	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"
	use_refresh_tokens_client_credentials = %t
}
	`, clientId, useRefreshTokensClientCredentials)
}

func testGluuOpenidClient_extraConfig(clientId string, extraConfig map[string]string) string {
	var sb strings.Builder
	sb.WriteString("{\n")
	for k, v := range extraConfig {
		sb.WriteString(fmt.Sprintf("\t\t\"%s\" = \"%s\"\n", k, v))
	}
	sb.WriteString("}")

	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"
	extra_config = %s
}
	`, clientId, sb.String())
}

func testGluuOpenidClient_oauth2DeviceAuthorizationGrantEnabled(clientId string, oauth2DeviceAuthorizationGrantEnabled bool) string {

	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   							  = "%s"
	access_type 							  = "CONFIDENTIAL"
	oauth2_device_authorization_grant_enabled = %t
}
	`, clientId, oauth2DeviceAuthorizationGrantEnabled)
}

func testGluuOpenidClient_oauth2DeviceTimes(clientId, oauth2DeviceCodeLifespan, oauth2DevicePollingInterval string, oauth2DeviceAuthorizationGrantEnabled bool) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   			 					= "%s"
	access_type 			 					= "CONFIDENTIAL"
	oauth2_device_authorization_grant_enabled 	= %t
	oauth2_device_code_lifespan 				= "%s"
	oauth2_device_polling_interval 				= "%s"
}
	`, clientId, oauth2DeviceAuthorizationGrantEnabled, oauth2DeviceCodeLifespan, oauth2DevicePollingInterval)
}
