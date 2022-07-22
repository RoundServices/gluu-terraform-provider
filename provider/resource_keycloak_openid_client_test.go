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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_basic(clientId),
				Check:  testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     testAccRealm.Realm + "/",
				ImportStateVerifyIgnore: []string{"exclude_session_state_from_auth_response"},
			},
		},
	})
}

func TestAccGluuOpenidClient_basic_with_consent(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_basic_with_consent(clientId),
				Check:  testAccCheckGluuOpenidClientExistsWithCorrectConsentSettings("gluu_openid_client.client"),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     testAccRealm.Realm + "/",
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_basic(clientId),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
					testAccCheckGluuOpenidClientFetch("gluu_openid_client.client", client),
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
				Check:  testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
			},
		},
	})
}

func TestAccGluuOpenidClient_updateRealm(t *testing.T) {
	t.Parallel()

	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_updateRealmBefore(clientId),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
					testAccCheckGluuOpenidClientBelongsToRealm("gluu_openid_client.client", testAccRealm.Realm),
				),
			},
			{
				Config: testGluuOpenidClient_updateRealmAfter(clientId),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
					testAccCheckGluuOpenidClientBelongsToRealm("gluu_openid_client.client", testAccRealmTwo.Realm),
				),
			},
		},
	})
}

func TestAccGluuOpenidClient_accessType(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_accessType(clientId, "CONFIDENTIAL"),
				Check:  testAccCheckGluuOpenidClientAccessType("gluu_openid_client.client", false, false),
			},
			{
				Config: testGluuOpenidClient_accessType(clientId, "PUBLIC"),
				Check:  testAccCheckGluuOpenidClientAccessType("gluu_openid_client.client", true, false),
			},
			{
				Config: testGluuOpenidClient_accessType(clientId, "BEARER-ONLY"),
				Check:  testAccCheckGluuOpenidClientAccessType("gluu_openid_client.client", false, true),
			},
		},
	})
}
func TestAccGluuOpenidClient_clientAuthenticatorType(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_clientAuthenticatorType(clientId, "client-secret"),
				Check:  testAccCheckGluuOpenidClientAuthenticatorType("gluu_openid_client.client", "client-secret"),
			},
			{
				Config: testGluuOpenidClient_clientAuthenticatorType(clientId, "client-jwt"),
				Check:  testAccCheckGluuOpenidClientAuthenticatorType("gluu_openid_client.client", "client-jwt"),
			},
			{
				Config: testGluuOpenidClient_clientAuthenticatorType(clientId, "client-secret-jwt"),
				Check:  testAccCheckGluuOpenidClientAuthenticatorType("gluu_openid_client.client", "client-secret-jwt"),
			},
			{
				Config: testGluuOpenidClient_clientAuthenticatorType(clientId, "client-x509"),
				Check:  testAccCheckGluuOpenidClientAuthenticatorType("gluu_openid_client.client", "client-x509"),
			},
		},
	})
}

func TestAccGluuOpenidClient_updateInPlace(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")
	enabled := randomBool()
	standardFlowEnabled := randomBool()
	implicitFlowEnabled := randomBool()
	directAccessGrantsEnabled := randomBool()
	serviceAccountsEnabled := randomBool()

	if !standardFlowEnabled {
		implicitFlowEnabled = !standardFlowEnabled
	}

	rootUrlBefore := "http://localhost:2222/" + acctest.RandString(20)
	openidClientBefore := &gluu.OpenidClient{
		ClientId:                  clientId,
		Name:                      acctest.RandString(10),
		Enabled:                   enabled,
		Description:               acctest.RandString(50),
		ClientSecret:              acctest.RandString(10),
		StandardFlowEnabled:       standardFlowEnabled,
		ImplicitFlowEnabled:       implicitFlowEnabled,
		DirectAccessGrantsEnabled: directAccessGrantsEnabled,
		ServiceAccountsEnabled:    serviceAccountsEnabled,
		ValidRedirectUris:         []string{acctest.RandString(10), acctest.RandString(10), acctest.RandString(10), acctest.RandString(10)},
		WebOrigins:                []string{acctest.RandString(10), acctest.RandString(10), acctest.RandString(10)},
		AdminUrl:                  acctest.RandString(20),
		BaseUrl:                   "http://localhost:2222/" + acctest.RandString(20),
		RootUrl:                   &rootUrlBefore,
	}

	standardFlowEnabled, implicitFlowEnabled = implicitFlowEnabled, standardFlowEnabled

	rootUrlAfter := "http://localhost:2222/" + acctest.RandString(20)
	openidClientAfter := &gluu.OpenidClient{
		ClientId:                  clientId,
		Name:                      acctest.RandString(10),
		Enabled:                   !enabled,
		Description:               acctest.RandString(50),
		ClientSecret:              acctest.RandString(10),
		StandardFlowEnabled:       standardFlowEnabled,
		ImplicitFlowEnabled:       implicitFlowEnabled,
		DirectAccessGrantsEnabled: !directAccessGrantsEnabled,
		ServiceAccountsEnabled:    !serviceAccountsEnabled,
		ValidRedirectUris:         []string{acctest.RandString(10), acctest.RandString(10)},
		WebOrigins:                []string{acctest.RandString(10), acctest.RandString(10), acctest.RandString(10), acctest.RandString(10), acctest.RandString(10)},
		AdminUrl:                  acctest.RandString(20),
		BaseUrl:                   "http://localhost:2222/" + acctest.RandString(20),
		RootUrl:                   &rootUrlAfter,
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_fromInterface(openidClientBefore),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
				),
			},
			{
				Config: testGluuOpenidClient_fromInterface(openidClientAfter),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
				),
			},
			{
				Config: testGluuOpenidClient_basic(clientId),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_backchannel(clientId, backchannelLogoutUrl, backchannelLogoutSessionRequired, backchannelLogoutRevokeOfflineSessions),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
					testAccCheckGluuOpenidClientHasBackchannelSettings("gluu_openid_client.client", backchannelLogoutUrl, backchannelLogoutSessionRequired, backchannelLogoutRevokeOfflineSessions),
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_frontchannel(clientId, frontchannelLogoutUrl, frontchannelLogoutEnabled),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
					testAccCheckGluuOpenidClientHasFrontchannelSettings("gluu_openid_client.client", frontchannelLogoutUrl, frontchannelLogoutEnabled),
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_AccessToken_basic(clientId, accessTokenLifespan),
				Check:  testAccCheckGluuOpenidClientExistsWithCorrectLifespan("gluu_openid_client.client", accessTokenLifespan),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     testAccRealm.Realm + "/",
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_ClientTimeouts(clientId,
					offlineSessionIdleTimeout, offlineSessionMaxLifespan, sessionIdleTimeout, sessionMaxLifespan),
				Check: testAccCheckGluuOpenidClientExistsWithCorrectClientTimeouts("gluu_openid_client.client",
					offlineSessionIdleTimeout, offlineSessionMaxLifespan, sessionIdleTimeout, sessionMaxLifespan,
				),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     testAccRealm.Realm + "/",
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_oauth2DeviceTimes(clientId,
					oauth2DeviceCodeLifespan, oauth2DevicePollingInterval, oauth2DeviceAuthorizationGrantEnabled,
				),
				Check: testAccCheckGluuOpenidClientOauth2Device("gluu_openid_client.client",
					oauth2DeviceCodeLifespan, oauth2DevicePollingInterval, oauth2DeviceAuthorizationGrantEnabled,
				),
			},
			{
				ResourceName:            "gluu_openid_client.client",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     testAccRealm.Realm + "/",
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_basic(clientId),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
					testAccCheckGluuOpenidClientHasNonEmptyClientSecret("gluu_openid_client.client"),
				),
			},
			{
				Config: testGluuOpenidClient_secret(clientId, clientSecret),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientExistsWithCorrectProtocol("gluu_openid_client.client"),
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
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
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
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

func TestAccGluuOpenidClient_pkceCodeChallengeMethod(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config:      testGluuOpenidClient_pkceChallengeMethod(clientId, "invalidMethod"),
				ExpectError: regexp.MustCompile(`expected pkce_code_challenge_method to be one of \[\ plain S256\], got invalidMethod`),
			},
			{
				Config: testGluuOpenidClient_omitPkceChallengeMethod(clientId),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasPkceCodeChallengeMethod("gluu_openid_client.client", ""),
					testAccCheckGluuOpenidClientHasExcludeSessionStateFromAuthResponse("gluu_openid_client.client", false),
				),
			},
			{
				Config: testGluuOpenidClient_pkceChallengeMethod(clientId, "plain"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasPkceCodeChallengeMethod("gluu_openid_client.client", "plain"),
					testAccCheckGluuOpenidClientHasExcludeSessionStateFromAuthResponse("gluu_openid_client.client", false),
				),
			},
			{
				Config: testGluuOpenidClient_pkceChallengeMethod(clientId, "S256"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasPkceCodeChallengeMethod("gluu_openid_client.client", "S256"),
					testAccCheckGluuOpenidClientHasExcludeSessionStateFromAuthResponse("gluu_openid_client.client", false),
				),
			},
			{
				Config: testGluuOpenidClient_pkceChallengeMethod(clientId, ""),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasPkceCodeChallengeMethod("gluu_openid_client.client", ""),
					testAccCheckGluuOpenidClientHasExcludeSessionStateFromAuthResponse("gluu_openid_client.client", false),
				),
			},
		},
	})
}

func TestAccGluuOpenidClient_excludeSessionStateFromAuthResponse(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_omitExcludeSessionStateFromAuthResponse(clientId, "plain"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasExcludeSessionStateFromAuthResponse("gluu_openid_client.client", false),
					testAccCheckGluuOpenidClientHasPkceCodeChallengeMethod("gluu_openid_client.client", "plain"),
				),
			},
			{
				Config: testGluuOpenidClient_excludeSessionStateFromAuthResponse(clientId, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasExcludeSessionStateFromAuthResponse("gluu_openid_client.client", false),
					testAccCheckGluuOpenidClientHasPkceCodeChallengeMethod("gluu_openid_client.client", ""),
				),
			},
			{
				Config: testGluuOpenidClient_excludeSessionStateFromAuthResponse(clientId, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasExcludeSessionStateFromAuthResponse("gluu_openid_client.client", true),
					testAccCheckGluuOpenidClientHasPkceCodeChallengeMethod("gluu_openid_client.client", ""),
				),
			},
			{
				Config: testGluuOpenidClient_excludeSessionStateFromAuthResponse(clientId, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGluuOpenidClientHasExcludeSessionStateFromAuthResponse("gluu_openid_client.client", false),
					testAccCheckGluuOpenidClientHasPkceCodeChallengeMethod("gluu_openid_client.client", ""),
				),
			},
		},
	})
}

func TestAccGluuOpenidClient_useRefreshTokens(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_useRefreshTokens(clientId, true),
				Check:  testAccCheckGluuOpenidClientUseRefreshTokens("gluu_openid_client.client", true),
			},
			{
				Config: testGluuOpenidClient_useRefreshTokens(clientId, false),
				Check:  testAccCheckGluuOpenidClientUseRefreshTokens("gluu_openid_client.client", false),
			},
		},
	})
}

func TestAccGluuOpenidClient_useRefreshTokensClientCredentials(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_useRefreshTokensClientCredentials(clientId, true),
				Check:  testAccCheckGluuOpenidClientUseRefreshTokensClientCredentials("gluu_openid_client.client", true),
			},
			{
				Config: testGluuOpenidClient_useRefreshTokensClientCredentials(clientId, false),
				Check:  testAccCheckGluuOpenidClientUseRefreshTokensClientCredentials("gluu_openid_client.client", false),
			},
		},
	})
}

func TestAccGluuOpenidClient_extraConfigInvalid(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config:      testGluuOpenidClient_extraConfig(clientId, map[string]string{"login_theme": "gluu"}),
				ExpectError: regexp.MustCompile(`extra_config key "login_theme" is not allowed`),
			},
		},
	})
}

func TestAccGluuOpenidClient_oauth2DeviceAuthorizationGrantEnabled(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_oauth2DeviceAuthorizationGrantEnabled(clientId, true),
				Check:  testAccCheckGluuOpenidClientOauth2DeviceAuthorizationGrantEnabled("gluu_openid_client.client", true),
			},
			{
				Config: testGluuOpenidClient_oauth2DeviceAuthorizationGrantEnabled(clientId, false),
				Check:  testAccCheckGluuOpenidClientOauth2DeviceAuthorizationGrantEnabled("gluu_openid_client.client", false),
			},
		},
	})
}

func testAccCheckGluuOpenidClientExistsWithCorrectProtocol(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Protocol != "openid-connect" {
			return fmt.Errorf("expected openid client to have openid-connect protocol, but got %s", client.Protocol)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientExistsWithCorrectConsentSettings(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.ConsentRequired != true {
			return fmt.Errorf("expected openid client to have ConsentRequired %v, but got %v", true, client.ConsentRequired)
		}

		if client.Attributes.DisplayOnConsentScreen != true {
			return fmt.Errorf("expected openid client to have DisplayClientOnConsentScreen %v, but got %v", true, client.Attributes.DisplayOnConsentScreen)
		}

		if client.Attributes.ConsentScreenText != "some consent screen text" {
			return fmt.Errorf("expected openid client to have ConsentScreenText %v, but got %v", "some consent screen text", client.Attributes.ConsentScreenText)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientHasBackchannelSettings(resourceName, backchannelLogoutUrl string, backchannelLogoutSessionRequired, backchannelLogoutRevokeOfflineSessions bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.BackchannelLogoutUrl != backchannelLogoutUrl {
			return fmt.Errorf("expected openid client to have backchannel logout url %s, got %s", backchannelLogoutUrl, client.Attributes.BackchannelLogoutUrl)
		}

		if bool(client.Attributes.BackchannelLogoutSessionRequired) != backchannelLogoutSessionRequired {
			return fmt.Errorf("expected openid client to have backchannel session required bool %t, got %t", backchannelLogoutSessionRequired, bool(client.Attributes.BackchannelLogoutSessionRequired))
		}

		if bool(client.Attributes.BackchannelLogoutRevokeOfflineTokens) != backchannelLogoutRevokeOfflineSessions {
			return fmt.Errorf("expected openid client to have backchannel revoke offline sessions bool %t, got %t", backchannelLogoutRevokeOfflineSessions, bool(client.Attributes.BackchannelLogoutRevokeOfflineTokens))
		}

		return nil
	}
}
func testAccCheckGluuOpenidClientHasFrontchannelSettings(resourceName, frontChannelLogoutUrl string, frontChannelLogoutEnabled bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.FrontchannelLogoutUrl != frontChannelLogoutUrl {
			return fmt.Errorf("expected openid client to have frontchannel logout url %s, got %s", frontChannelLogoutUrl, client.Attributes.FrontchannelLogoutUrl)
		}

		if client.FrontChannelLogoutEnabled != frontChannelLogoutEnabled {
			return fmt.Errorf("expected openid client to have frontchannel enabled bool %t, got %t", frontChannelLogoutEnabled, client.FrontChannelLogoutEnabled)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientExistsWithCorrectLifespan(resourceName string, accessTokenLifespan string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.AccessTokenLifespan != accessTokenLifespan {
			return fmt.Errorf("expected openid client to have access token lifespan set to %s, but got %s", accessTokenLifespan, client.Attributes.AccessTokenLifespan)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientExistsWithCorrectClientTimeouts(resourceName string,
	offlineSessionIdleTimeout string, offlineSessionMaxLifespan string,
	sessionIdleTimeout string, sessionMaxLifespan string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.ClientOfflineSessionIdleTimeout != offlineSessionIdleTimeout {
			return fmt.Errorf("expected openid client to have client offline session idle timeout set to %s, but got %s", offlineSessionIdleTimeout, client.Attributes.ClientOfflineSessionIdleTimeout)
		}

		if client.Attributes.ClientOfflineSessionMaxLifespan != offlineSessionMaxLifespan {
			return fmt.Errorf("expected openid client to have client offline session max lifespan set to %s, but got %s", offlineSessionMaxLifespan, client.Attributes.ClientOfflineSessionMaxLifespan)
		}

		if client.Attributes.ClientSessionIdleTimeout != sessionIdleTimeout {
			return fmt.Errorf("expected openid client to have client session idle timeout set to %s, but got %s", sessionIdleTimeout, client.Attributes.ClientSessionIdleTimeout)
		}

		if client.Attributes.ClientSessionMaxLifespan != sessionMaxLifespan {
			return fmt.Errorf("expected openid client to have client session max lifespan set to %s, but got %s", sessionMaxLifespan, client.Attributes.ClientSessionMaxLifespan)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientOauth2Device(resourceName string,
	oauth2DeviceCodeLifespan string, Oauth2DevicePollingInterval string, oauth2DeviceAuthorizationGrantEnabled bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.Oauth2DeviceAuthorizationGrantEnabled != gluu.GluuBoolQuoted(oauth2DeviceAuthorizationGrantEnabled) {
			return fmt.Errorf("expected openid client to have device authorizationen granted enabled set to %t, but got %v", oauth2DeviceAuthorizationGrantEnabled, client.Attributes.Oauth2DeviceAuthorizationGrantEnabled)
		}

		if client.Attributes.Oauth2DeviceCodeLifespan != oauth2DeviceCodeLifespan {
			return fmt.Errorf("expected openid client to have device code lifespan set to %s, but got %s", oauth2DeviceCodeLifespan, client.Attributes.Oauth2DeviceCodeLifespan)
		}

		if client.Attributes.Oauth2DevicePollingInterval != Oauth2DevicePollingInterval {
			return fmt.Errorf("expected openid client to have device polling interval set to %s, but got %s", Oauth2DevicePollingInterval, client.Attributes.Oauth2DevicePollingInterval)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientFetch(resourceName string, client *gluu.OpenidClient) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		fetchedClient, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		client.Id = fetchedClient.Id
		client.RealmId = fetchedClient.RealmId

		return nil
	}
}

func testAccCheckGluuOpenidClientAccessType(resourceName string, public, bearer bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.PublicClient != public {
			return fmt.Errorf("expected openid client to have public set to %t, but got %t", public, client.PublicClient)
		}

		if client.BearerOnly != bearer {
			return fmt.Errorf("expected openid client to have bearer set to %t, but got %t", bearer, client.BearerOnly)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientAuthenticatorType(resourceName string, authType string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.ClientAuthenticatorType != authType {
			return fmt.Errorf("expected openid client to have client_authenticator_type set to %s, but got %s", authType, client.ClientAuthenticatorType)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientBelongsToRealm(resourceName, realm string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.RealmId != realm {
			return fmt.Errorf("expected openid client %s to have realm_id of %s, but got %s", client.ClientId, realm, client.RealmId)
		}

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
			return fmt.Errorf("expected openid client %s to have secret value of %s, but got %s", client.ClientId, secret, client.ClientSecret)
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
			return fmt.Errorf("expected openid client %s to have non empty secret value", client.ClientId)
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
			realm := rs.Primary.Attributes["realm_id"]

			client, _ := gluuClient.GetOpenidClient(testCtx, realm, id)
			if client != nil {
				return fmt.Errorf("openid client %s still exists", id)
			}
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientHasPkceCodeChallengeMethod(resourceName, pkceCodeChallengeMethod string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.PkceCodeChallengeMethod != pkceCodeChallengeMethod {
			return fmt.Errorf("expected openid client %s to have pkce code challenge method value of %s, but got %s", client.ClientId, pkceCodeChallengeMethod, client.Attributes.PkceCodeChallengeMethod)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientHasExcludeSessionStateFromAuthResponse(resourceName string, excludeSessionStateFromAuthResponse GluuBoolQuoted) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.ExcludeSessionStateFromAuthResponse != excludeSessionStateFromAuthResponse {
			return fmt.Errorf("expected openid client %s to have exclude_session_state_from_auth_response value of %t, but got %t", client.ClientId, excludeSessionStateFromAuthResponse, client.Attributes.ExcludeSessionStateFromAuthResponse)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientUseRefreshTokens(resourceName string, useRefreshTokens bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.UseRefreshTokens != gluu.GluuBoolQuoted(useRefreshTokens) {
			return fmt.Errorf("expected openid client to have use refresh tokens set to %t, but got %v", useRefreshTokens, client.Attributes.UseRefreshTokens)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientUseRefreshTokensClientCredentials(resourceName string, useRefreshTokensClientCredentials bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.UseRefreshTokensClientCredentials != gluu.GluuBoolQuoted(useRefreshTokensClientCredentials) {
			return fmt.Errorf("expected openid client to have use refresh tokens client credentials set to %t, but got %v", useRefreshTokensClientCredentials, client.Attributes.UseRefreshTokensClientCredentials)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientOauth2DeviceAuthorizationGrantEnabled(resourceName string, oauth2DeviceAuthorizationGrantEnabled bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.Oauth2DeviceAuthorizationGrantEnabled != gluu.GluuBoolQuoted(oauth2DeviceAuthorizationGrantEnabled) {
			return fmt.Errorf("expected openid client to have device authorization grant enabled set to %t, but got %v", oauth2DeviceAuthorizationGrantEnabled, client.Attributes.Oauth2DeviceAuthorizationGrantEnabled)
		}

		return nil
	}
}

func testAccCheckGluuOpenidClientExtraConfig(resourceName string, key string, value string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := getOpenidClientFromState(s, resourceName)
		if err != nil {
			return err
		}

		if client.Attributes.ExtraConfig[key] != value {
			return fmt.Errorf("expected openid client to have attribute %v set to %v, but got %v", key, value, client.Attributes.ExtraConfig[key])
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
	realm := rs.Primary.Attributes["realm_id"]

	client, err := gluuClient.GetOpenidClient(testCtx, realm, id)
	if err != nil {
		return nil, fmt.Errorf("error getting openid client %s: %s", id, err)
	}

	return client, nil
}

func testGluuOpenidClient_basic(clientId string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"
}
	`, testAccRealm.Realm, clientId)
}

func testGluuOpenidClient_basic_with_consent(clientId string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   				= "%s"
	realm_id    				= data.gluu_realm.realm.id
	access_type 				= "CONFIDENTIAL"
	consent_required            = true
	display_on_consent_screen	= true
	consent_screen_text         = "some consent screen text"
}
	`, testAccRealm.Realm, clientId)
}

func testGluuOpenidClient_AccessToken_basic(clientId, accessTokenLifespan string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   		  = "%s"
	realm_id    		  = data.gluu_realm.realm.id
	access_type 		  = "CONFIDENTIAL"
	access_token_lifespan = "%s"
}
	`, testAccRealm.Realm, clientId, accessTokenLifespan)
}

func testGluuOpenidClient_ClientTimeouts(clientId,
	offlineSessionIdleTimeout string, offlineSessionMaxLifespan string,
	sessionIdleTimeout string, sessionMaxLifespan string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   		  = "%s"
	realm_id    		  = data.gluu_realm.realm.id
	access_type 		  = "CONFIDENTIAL"

	client_offline_session_idle_timeout = "%s"
	client_offline_session_max_lifespan = "%s"
	client_session_idle_timeout         = "%s"
	client_session_max_lifespan         = "%s"
}
	`, testAccRealm.Realm, clientId, offlineSessionIdleTimeout, offlineSessionMaxLifespan, sessionIdleTimeout, sessionMaxLifespan)
}

func testGluuOpenidClient_accessType(clientId, accessType string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "%s"
}
	`, testAccRealm.Realm, clientId, accessType)
}

func testGluuOpenidClient_clientAuthenticatorType(clientId, authType string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	realm_id                  = data.gluu_realm.realm.id
	client_id                 = "%s"
	access_type               = "CONFIDENTIAL"
	client_authenticator_type = "%s"
}
	`, testAccRealm.Realm, clientId, authType)
}

func testGluuOpenidClient_pkceChallengeMethod(clientId, pkceChallengeMethod string) string {

	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"
	pkce_code_challenge_method = "%s"
}
	`, testAccRealm.Realm, clientId, pkceChallengeMethod)
}

func testGluuOpenidClient_excludeSessionStateFromAuthResponse(clientId string, excludeSessionStateFromAuthResponse bool) string {

	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"
	exclude_session_state_from_auth_response = %t
}
	`, testAccRealm.Realm, clientId, excludeSessionStateFromAuthResponse)
}

func testGluuOpenidClient_omitPkceChallengeMethod(clientId string) string {

	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"
}
	`, testAccRealm.Realm, clientId)
}

func testGluuOpenidClient_omitExcludeSessionStateFromAuthResponse(clientId, pkceChallengeMethod string) string {

	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"
    pkce_code_challenge_method = "%s"
}
	`, testAccRealm.Realm, clientId, pkceChallengeMethod)
}

func testGluuOpenidClient_updateRealmBefore(clientId string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm_1" {
	realm = "%s"
}

data "gluu_realm" "realm_2" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm_1.id
	access_type = "BEARER-ONLY"
}
	`, testAccRealm.Realm, testAccRealmTwo.Realm, clientId)
}

func testGluuOpenidClient_updateRealmAfter(clientId string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm_1" {
	realm = "%s"
}

data "gluu_realm" "realm_2" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm_2.id
	access_type = "BEARER-ONLY"
}
	`, testAccRealm.Realm, testAccRealmTwo.Realm, clientId)
}

func testGluuOpenidClient_fromInterface(openidClient *gluu.OpenidClient) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id                    = "%s"
	realm_id                     = data.gluu_realm.realm.id
	name                         = "%s"
	enabled                      = %t
	description                  = "%s"

	access_type                  = "CONFIDENTIAL"
	client_secret                = "%s"

	standard_flow_enabled        = %t
	implicit_flow_enabled        = %t
	direct_access_grants_enabled = %t
	service_accounts_enabled     = %t

	valid_redirect_uris          = %s
	web_origins                  = %s
	admin_url					 = "%s"
	base_url                     = "%s"
	root_url                     = "%s"

	backchannel_logout_url                     = "%s"
	backchannel_logout_session_required        = %t
	backchannel_logout_revoke_offline_sessions = %t
}
	`, testAccRealm.Realm, openidClient.ClientId, openidClient.Name, openidClient.Enabled, openidClient.Description, openidClient.ClientSecret, openidClient.StandardFlowEnabled, openidClient.ImplicitFlowEnabled, openidClient.DirectAccessGrantsEnabled, openidClient.ServiceAccountsEnabled, arrayOfStringsForTerraformResource(openidClient.ValidRedirectUris), arrayOfStringsForTerraformResource(openidClient.WebOrigins), openidClient.AdminUrl, openidClient.BaseUrl, *openidClient.RootUrl, openidClient.Attributes.BackchannelLogoutUrl, openidClient.Attributes.BackchannelLogoutSessionRequired, openidClient.Attributes.BackchannelLogoutRevokeOfflineTokens)
}

func testGluuOpenidClient_backchannel(clientId, backchannelLogoutUrl string, backchannelLogoutSessionRequired, backchannelLogoutRevokeOfflineSessions bool) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"

	backchannel_logout_url                     = "%s"
	backchannel_logout_session_required        = %t
	backchannel_logout_revoke_offline_sessions = %t
}
	`, testAccRealm.Realm, clientId, backchannelLogoutUrl, backchannelLogoutSessionRequired, backchannelLogoutRevokeOfflineSessions)
}

func testGluuOpenidClient_frontchannel(clientId, frontchannelLogoutUrl string, frontchannelLogoutEnabled bool) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"

	frontchannel_logout_url     = "%s"
	frontchannel_logout_enabled = %t
}
	`, testAccRealm.Realm, clientId, frontchannelLogoutUrl, frontchannelLogoutEnabled)
}

func testGluuOpenidClient_secret(clientId, clientSecret string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id     = "%s"
	realm_id      = data.gluu_realm.realm.id
	access_type   = "CONFIDENTIAL"
	client_secret = "%s"
}
	`, testAccRealm.Realm, clientId, clientSecret)
}

func testGluuOpenidClient_invalidRedirectUris(clientId, accessType string, standardFlowEnabled, implicitFlowEnabled bool) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id             = "%s"
	realm_id              = data.gluu_realm.realm.id
	access_type           = "%s"

	standard_flow_enabled = %t
	implicit_flow_enabled = %t
}
	`, testAccRealm.Realm, clientId, accessType, standardFlowEnabled, implicitFlowEnabled)
}

func testGluuOpenidClient_invalidPublicClientWithClientCredentials(clientId string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id                = "%s"
	realm_id                 = data.gluu_realm.realm.id
	access_type              = "PUBLIC"

	service_accounts_enabled = true
}
	`, testAccRealm.Realm, clientId)
}

func testGluuOpenidClient_bearerOnlyClientsCannotIssueTokens(clientId string, standardFlowEnabled, implicitFlowEnabled, directAccessGrantsEnabled, serviceAccountsEnabled bool) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id                    = "%s"
	realm_id                     = data.gluu_realm.realm.id
	access_type                  = "BEARER-ONLY"

	standard_flow_enabled        = %t
	implicit_flow_enabled        = %t
	direct_access_grants_enabled = %t
	service_accounts_enabled     = %t
}
	`, testAccRealm.Realm, clientId, standardFlowEnabled, implicitFlowEnabled, directAccessGrantsEnabled, serviceAccountsEnabled)
}

func testGluuOpenidClient_authenticationFlowBindingOverrides(clientId string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_authentication_flow" "another_flow" {
  alias    = "anotherFlow"
  realm_id = data.gluu_realm.realm.id
  description = "this is another flow"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "PUBLIC"
	authentication_flow_binding_overrides {
		browser_id = "${gluu_authentication_flow.another_flow.id}"
		direct_grant_id = "${gluu_authentication_flow.another_flow.id}"
	}
}
	`, testAccRealm.Realm, clientId)
}

func testGluuOpenidClient_withoutAuthenticationFlowBindingOverrides(clientId string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_authentication_flow" "another_flow" {
  alias    = "anotherFlow"
  realm_id = data.gluu_realm.realm.id
  description = "this is another flow"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "PUBLIC"
}
	`, testAccRealm.Realm, clientId)
}

func testGluuOpenidClient_loginTheme(clientId, loginTheme string) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "PUBLIC"
	login_theme = "%s"
}
	`, testAccRealm.Realm, clientId, loginTheme)
}

func testGluuOpenidClient_useRefreshTokens(clientId string, useRefreshTokens bool) string {

	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"
	use_refresh_tokens = %t
}
	`, testAccRealm.Realm, clientId, useRefreshTokens)
}

func testGluuOpenidClient_useRefreshTokensClientCredentials(clientId string, useRefreshTokensClientCredentials bool) string {

	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"
	use_refresh_tokens_client_credentials = %t
}
	`, testAccRealm.Realm, clientId, useRefreshTokensClientCredentials)
}

func testGluuOpenidClient_extraConfig(clientId string, extraConfig map[string]string) string {
	var sb strings.Builder
	sb.WriteString("{\n")
	for k, v := range extraConfig {
		sb.WriteString(fmt.Sprintf("\t\t\"%s\" = \"%s\"\n", k, v))
	}
	sb.WriteString("}")

	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   = "%s"
	realm_id    = data.gluu_realm.realm.id
	access_type = "CONFIDENTIAL"
	extra_config = %s
}
	`, testAccRealm.Realm, clientId, sb.String())
}

func testGluuOpenidClient_oauth2DeviceAuthorizationGrantEnabled(clientId string, oauth2DeviceAuthorizationGrantEnabled bool) string {

	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   							  = "%s"
	realm_id    							  = data.gluu_realm.realm.id
	access_type 							  = "CONFIDENTIAL"
	oauth2_device_authorization_grant_enabled = %t
}
	`, testAccRealm.Realm, clientId, oauth2DeviceAuthorizationGrantEnabled)
}

func testGluuOpenidClient_oauth2DeviceTimes(clientId, oauth2DeviceCodeLifespan, oauth2DevicePollingInterval string, oauth2DeviceAuthorizationGrantEnabled bool) string {
	return fmt.Sprintf(`
data "gluu_realm" "realm" {
	realm = "%s"
}

resource "gluu_openid_client" "client" {
	client_id   			 					= "%s"
	realm_id    		     					= data.gluu_realm.realm.id
	access_type 			 					= "CONFIDENTIAL"
	oauth2_device_authorization_grant_enabled 	= %t
	oauth2_device_code_lifespan 				= "%s"
	oauth2_device_polling_interval 				= "%s"
}
	`, testAccRealm.Realm, clientId, oauth2DeviceAuthorizationGrantEnabled, oauth2DeviceCodeLifespan, oauth2DevicePollingInterval)
}
