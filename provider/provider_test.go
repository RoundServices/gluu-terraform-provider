package provider

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/meta"
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
	userAgent := fmt.Sprintf("HashiCorp Terraform/%s (+https://www.terraform.io) Terraform Plugin SDK/%s", schema.Provider{}.TerraformVersion, meta.SDKVersionString())
	gluuClient, _ = gluu.NewGluuClient(testCtx, os.Getenv("GLUU_URL"), "/auth", os.Getenv("GLUU_CLIENT_ID"), os.Getenv("GLUU_CLIENT_SECRET"), "", "", true, 5, "", false, userAgent, map[string]string{
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
