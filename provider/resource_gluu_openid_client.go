package provider

import (
	"context"
	"errors"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/RoundServices/gluu-terraform-provider/gluu"
)

func resourceGluuOpenidClient() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceGluuOpenidClientCreate,
		ReadContext:   resourceGluuOpenidClientRead,
		DeleteContext: resourceGluuOpenidClientDelete,
		UpdateContext: resourceGluuOpenidClientUpdate,
		Importer: &schema.ResourceImporter{
			StateContext: resourceGluuOpenidClientImport,
		},
		Schema: map[string]*schema.Schema{
			"inum": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"redirect_uris": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
				Optional: true,
			},
		},
	}
}

func getOpenidClientFromData(data *schema.ResourceData) (*gluu.OpenidClient, error) {
	validRedirectUris := make([]string, 0)
	validRedirectUrisData, validRedirectUrisOk := data.GetOk("redirect_uris")


	if validRedirectUrisOk {
		for _, validRedirectUri := range validRedirectUrisData.(*schema.Set).List() {
			validRedirectUris = append(validRedirectUris, validRedirectUri.(string))
		}
	}

	openidClient := &gluu.OpenidClient{
		Id:                  data.Id(),
		Inum:                data.Get("inum").(string),
		RedirectUris:        validRedirectUris,
	}
	return openidClient, nil
}

func setOpenidClientData(ctx context.Context, gluuClient *gluu.GluuClient, data *schema.ResourceData, client *gluu.OpenidClient) error {
	data.SetId(client.Id)
	data.Set("inum", client.Inum)
	data.Set("redirect_uris", client.RedirectUris)

	return nil
}

func resourceGluuOpenidClientCreate(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	gluuClient := meta.(*gluu.GluuClient)

	client, err := getOpenidClientFromData(data)
	if err != nil {
		return diag.FromErr(err)
	}

	err = gluuClient.NewOpenidClient(ctx, client)
	if err != nil {
		return diag.FromErr(err)
	}

	err = setOpenidClientData(ctx, gluuClient, data, client)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceGluuOpenidClientRead(ctx, data, meta)
}

func resourceGluuOpenidClientRead(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	gluuClient := meta.(*gluu.GluuClient)

	id := data.Id()

	client, err := gluuClient.GetOpenidClient(ctx, id)
	if err != nil {
		return diag.FromErr(err)
	}

	err = setOpenidClientData(ctx, gluuClient, data, client)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceGluuOpenidClientUpdate(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	gluuClient := meta.(*gluu.GluuClient)

	client, err := getOpenidClientFromData(data)
	if err != nil {
		return diag.FromErr(err)
	}

	err = gluuClient.UpdateOpenidClient(ctx, client)
	if err != nil {
		return diag.FromErr(err)
	}

	err = setOpenidClientData(ctx, gluuClient, data, client)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceGluuOpenidClientDelete(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	gluuClient := meta.(*gluu.GluuClient)

	id := data.Id()
	client, err := gluuClient.GetOpenidClient(ctx, id)
	if err != nil {
		return diag.FromErr(err)
	}
	return diag.FromErr(gluuClient.DeleteOpenidClient(ctx, client))
}

func resourceGluuOpenidClientImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	gluuClient := meta.(*gluu.GluuClient)

	_, err := gluuClient.GetOpenidClient(ctx, d.Id())
	if err != nil {
		return nil, err
	}

	diagnostics := resourceGluuOpenidClientRead(ctx, d, meta)
	if diagnostics.HasError() {
		return nil, errors.New(diagnostics[0].Summary)
	}

	return []*schema.ResourceData{d}, nil
}
