package provider

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func keys(data map[string]string) []string {
	var result []string
	for k := range data {
		result = append(result, k)
	}
	return result
}

func handleNotFoundError(ctx context.Context, err error, data *schema.ResourceData) diag.Diagnostics {
	return diag.FromErr(err)
}
