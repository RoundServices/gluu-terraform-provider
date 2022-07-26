package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/RoundServices/gluu-terraform-provider/gluu"
)

func GluuProvider(client *gluu.GluuClient) *schema.Provider {
	provider := &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"gluu_openid_client":           resourceGluuOpenidClient(),
		},
		Schema: map[string]*schema.Schema{
			"client_id": {
				Required:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("GLUU_CLIENT_ID", nil),
			},
			"client_secret": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("GLUU_CLIENT_SECRET", nil),
			},
			"url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The base URL of the Gluu instance, before `/auth`",
				DefaultFunc: schema.EnvDefaultFunc("GLUU_URL", nil),
			},
			"initial_login": {
				Optional:    true,
				Type:        schema.TypeBool,
				Description: "Whether or not to login to Gluu instance on provider initialization",
				Default:     true,
			},
			"client_timeout": {
				Optional:    true,
				Type:        schema.TypeInt,
				Description: "Timeout (in seconds) of the Gluu client",
				DefaultFunc: schema.EnvDefaultFunc("GLUU_CLIENT_TIMEOUT", 15),
			},
			"root_ca_certificate": {
				Optional:    true,
				Type:        schema.TypeString,
				Description: "Allows x509 calls using an unknown CA certificate (for development purposes)",
				Default:     "",
			},
			"tls_insecure_skip_verify": {
				Optional:    true,
				Type:        schema.TypeBool,
				Description: "Allows ignoring insecure certificates when set to true. Defaults to false. Disabling security check is dangerous and should be avoided.",
				Default:     false,
			},
			"base_path": {
				Optional:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("GLUU_BASE_PATH", ""),
			},
			"additional_headers": {
				Optional: true,
				Type:     schema.TypeMap,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}

	provider.ConfigureContextFunc = func(ctx context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
		if client != nil {
			return client, nil
		}

		url := data.Get("url").(string)
		basePath := data.Get("base_path").(string)
		clientId := data.Get("client_id").(string)
		clientSecret := data.Get("client_secret").(string)
		initialLogin := data.Get("initial_login").(bool)
		clientTimeout := data.Get("client_timeout").(int)
		tlsInsecureSkipVerify := data.Get("tls_insecure_skip_verify").(bool)
		rootCaCertificate := data.Get("root_ca_certificate").(string)
		additionalHeaders := make(map[string]string)
		for k, v := range data.Get("additional_headers").(map[string]interface{}) {
			additionalHeaders[k] = v.(string)
		}

		var diags diag.Diagnostics

		gluuClient, err := gluu.NewGluuClient(ctx, url, basePath, clientId, clientSecret, initialLogin, clientTimeout, rootCaCertificate, tlsInsecureSkipVerify, additionalHeaders)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "error initializing gluu provider",
				Detail:   err.Error(),
			})
		}

		return gluuClient, diags
	}

	return provider
}
