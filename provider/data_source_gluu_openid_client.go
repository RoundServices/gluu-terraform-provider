package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/RoundServices/gluu-terraform-provider/gluu"
)

func dataSourceGluuOpenidClient() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceGluuOpenidClientRead,

		Schema: map[string]*schema.Schema{
			"dn": {
				Type:     schema.TypeString,
				Required: true,
			},
			"inum": {
				Type:     schema.TypeString,
				Required: true,
			},
			"displayName": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"redirectUris": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
				Computed: true,
			},
		},
	}
}

func dataSourceGluuOpenidClientRead(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	gluuClient := meta.(*gluu.GluuClient)

	clientId := data.Get("inum").(string)

	client, err := gluuClient.GetOpenidClient(ctx, clientId)
	if err != nil {
		return handleNotFoundError(ctx, err, data)
	}

	err = setOpenidClientData(ctx, gluuClient, data, client)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}
