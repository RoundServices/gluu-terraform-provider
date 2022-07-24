package gluu

import (
	"context"
	"fmt"
)

type OpenidClient struct {
	Id                 string            `json:"id,omitempty"`
	Dn                 string            `json:"dn"`
	Inum               string            `json:"inum"`
	DisplayName        string            `json:"displayName"`
	ClientSecret       string            `json:"secret,omitempty"`
	RedirectUris       []string          `json:"redirectUris"`
}

type OpenidClientSecret struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (gluuClient *GluuClient) ValidateOpenidClient(ctx context.Context, client *OpenidClient) error {
	return nil
}

func (gluuClient *GluuClient) NewOpenidClient(ctx context.Context, client *OpenidClient) error {

	_, _, err := gluuClient.post(ctx, "/clients", client)
	if err != nil {
		return err
	}

	return nil
}

func (gluuClient *GluuClient) GetOpenidClients(ctx context.Context, withSecrets bool) ([]*OpenidClient, error) {
	var clients []*OpenidClient
	var clientSecret OpenidClientSecret

	err := gluuClient.get(ctx, "/clients", &clients, nil)
	if err != nil {
		return nil, err
	}

	for _, client := range clients {
		if !withSecrets {
			continue
		}

		client.ClientSecret = clientSecret.Value
	}

	return clients, nil
}

func (gluuClient *GluuClient) GetOpenidClient(ctx context.Context, id string) (*OpenidClient, error) {
	var client OpenidClient
	var clientSecret OpenidClientSecret

	err := gluuClient.get(ctx, fmt.Sprintf("/clients/%s", client.Inum), &client, nil)
	if err != nil {
		return nil, err
	}

	client.ClientSecret = clientSecret.Value

	return &client, nil
}

func (gluuClient *GluuClient) UpdateOpenidClient(ctx context.Context, client *OpenidClient) error {

	return gluuClient.put(ctx, fmt.Sprintf("/clients/%s", client.Inum), client)
}

func (gluuClient *GluuClient) DeleteOpenidClient(ctx context.Context, client *OpenidClient) error {
	return gluuClient.delete(ctx, fmt.Sprintf("/clients/%s", client.Inum), nil)
}

