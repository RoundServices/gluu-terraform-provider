package provider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/RoundServices/gluu-terraform-provider/gluu"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

type GluuBoolQuoted bool

func TestAccGluuOpenidClient_basic(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		CheckDestroy: testAccCheckGluuOpenidClientDestroy(),
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

func TestAccGluuOpenidClient_createAfterManualDestroy(t *testing.T) {
	t.Parallel()
	var client = &gluu.OpenidClient{}

	clientId := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		CheckDestroy: testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_basic(clientId),
				Check:  resource.ComposeTestCheckFunc(),
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
		CheckDestroy: testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient(clientId),
				Check:  resource.ComposeTestCheckFunc(),
			},
		},
	})
}

func TestAccGluuOpenidClient_updateInPlace(t *testing.T) {
	t.Parallel()
	clientId := acctest.RandomWithPrefix("tf-acc")

	openidClientBefore := &gluu.OpenidClient{
		Inum:         clientId,
		RedirectUris: []string{acctest.RandString(10), acctest.RandString(10), acctest.RandString(10), acctest.RandString(10)},
	}

	openidClientAfter := &gluu.OpenidClient{
		Inum:         clientId,
		RedirectUris: []string{acctest.RandString(10), acctest.RandString(10)},
	}

	resource.Test(t, resource.TestCase{
		CheckDestroy: testAccCheckGluuOpenidClientDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testGluuOpenidClient_fromInterface(openidClientBefore),
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				Config: testGluuOpenidClient_fromInterface(openidClientAfter),
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				Config: testGluuOpenidClient_basic(clientId),
				Check:  resource.ComposeTestCheckFunc(),
			},
		},
	})
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

func testGluuOpenidClient_basic(clientId string) string {
	return fmt.Sprintf(`
resource "gluu_openid_client" "client" {
	client_id   = "%s"
	access_type = "CONFIDENTIAL"
}
	`, clientId)
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
	redirectUris           = %s
}
	`, openidClient.Inum, arrayOfStringsForTerraformResource(openidClient.RedirectUris))
}

// Returns a slice of strings in the format ["foo", "bar"] for
// use within terraform resource definitions for acceptance tests
func arrayOfStringsForTerraformResource(parts []string) string {
	var tfStrings []string

	for _, part := range parts {
		tfStrings = append(tfStrings, fmt.Sprintf(`"%s"`, part))
	}

	return "[" + strings.Join(tfStrings, ", ") + "]"
}
