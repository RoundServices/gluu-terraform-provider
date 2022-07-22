package gluu

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"os"
	"strconv"
	"testing"
)

var requiredEnvironmentVariables = []string{
	"GLUU_CLIENT_ID",
	"GLUU_URL",
	"GLUU_REALM",
}

// Some actions, such as creating a realm, require a refresh
// before a GET can be performed on that realm
//
// This test ensures that, after creating a realm and performing
// a GET, the access token and refresh token have changed
//
// Any action that returns a 403 or a 401 could be used for this test
// Creating a realm is just the only one I'm aware of
//
// This appears to have been fixed as of Gluu 12.x
func TestAccGluuApiClientRefresh(t *testing.T) {
	ctx := context.Background()

	for _, requiredEnvironmentVariable := range requiredEnvironmentVariables {
		if value := os.Getenv(requiredEnvironmentVariable); value == "" {
			t.Fatalf("%s must be set before running acceptance tests.", requiredEnvironmentVariable)
		}
	}

	if v := os.Getenv("GLUU_CLIENT_SECRET"); v == "" {
		if v := os.Getenv("GLUU_USER"); v == "" {
			t.Fatal("GLUU_USER must be set for acceptance tests")
		}
		if v := os.Getenv("GLUU_PASSWORD"); v == "" {
			t.Fatal("GLUU_PASSWORD must be set for acceptance tests")
		}
	}

	// Convert GLUU_CLIENT_TIMEOUT to int
	clientTimeout, err := strconv.Atoi(os.Getenv("GLUU_CLIENT_TIMEOUT"))
	if err != nil {
		t.Fatal("GLUU_CLIENT_TIMEOUT must be an integer")
	}

	gluuClient, err := NewGluuClient(ctx, os.Getenv("GLUU_URL"), "/auth", os.Getenv("GLUU_CLIENT_ID"), os.Getenv("GLUU_CLIENT_SECRET"), os.Getenv("GLUU_REALM"), os.Getenv("GLUU_USER"), os.Getenv("GLUU_PASSWORD"), true, clientTimeout, "", false, "", map[string]string{
		"foo": "bar",
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	realmName := "terraform-" + acctest.RandString(10)
	realm := &Realm{
		Realm: realmName,
		Id:    realmName,
	}

	err = gluuClient.NewRealm(ctx, realm)
	if err != nil {
		t.Fatalf("%s", err)
	}

	var oldAccessToken, oldRefreshToken, oldTokenType string

	// A following GET for this realm will result in a 403, so we should save the current access and refresh token
	if gluuClient.clientCredentials.GrantType == "client_credentials" {
		oldAccessToken = gluuClient.clientCredentials.AccessToken
		oldRefreshToken = gluuClient.clientCredentials.RefreshToken
		oldTokenType = gluuClient.clientCredentials.TokenType
	}

	_, err = gluuClient.GetRealm(ctx, realmName) // This should not fail since it will automatically refresh and try again
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Clean up - the realm doesn't need to exist in order for us to assert against the refreshed tokens
	err = gluuClient.DeleteRealm(ctx, realmName)
	if err != nil {
		t.Fatalf("%s", err)
	}

	if gluuClient.clientCredentials.GrantType == "client_credentials" {
		newAccessToken := gluuClient.clientCredentials.AccessToken
		newRefreshToken := gluuClient.clientCredentials.RefreshToken
		newTokenType := gluuClient.clientCredentials.TokenType

		if oldAccessToken == newAccessToken {
			t.Fatalf("expected access token to update after refresh")
		}

		if oldRefreshToken == newRefreshToken {
			t.Fatalf("expected refresh token to update after refresh")
		}

		if oldTokenType != newTokenType {
			t.Fatalf("expected token type to remain the same after refresh")
		}
	}
}
