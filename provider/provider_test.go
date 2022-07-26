package provider

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"os"
	"testing"
	"github.com/RoundServices/gluu-terraform-provider/gluu"
)

var testAccProviderFactories map[string]func() (*schema.Provider, error)
var testAccProvider *schema.Provider
var gluuClient *gluu.GluuClient
var testCtx context.Context

var requiredEnvironmentVariables = []string{
	"GLUU_CLIENT_ID",
	"GLUU_CLIENT_SECRET",
	"GLUU_URL",
}

func init() {
	testCtx = context.Background()
	gluuClient, _ = gluu.NewGluuClient(testCtx, os.Getenv("GLUU_URL"), "", os.Getenv("GLUU_CLIENT_ID"), os.Getenv("GLUU_CLIENT_SECRET"), true, 5, "", false, map[string]string{
		"foo": "bar",
	})
	testAccProvider = GluuProvider(gluuClient)
	testAccProviderFactories = map[string]func() (*schema.Provider, error){
		"gluu": func() (*schema.Provider, error) {
			return testAccProvider, nil
		},
	}
}

func TestProvider(t *testing.T) {
	t.Parallel()

	if err := testAccProvider.InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func testAccPreCheck(t *testing.T) {
	for _, requiredEnvironmentVariable := range requiredEnvironmentVariables {
		if value := os.Getenv(requiredEnvironmentVariable); value == "" {
			t.Fatalf("%s must be set before running acceptance tests.", requiredEnvironmentVariable)
		}
	}
}
