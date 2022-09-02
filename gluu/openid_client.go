package gluu

import (
	"context"
	"encoding/json"
	"fmt"
)

type OpenidClient struct {
	Inum         string   `json:"inum"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	RedirectUris []string `json:"redirectUris"`
}

type OpenidClientSecret struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (gluuClient *GluuClient) NewOpenidClient(ctx context.Context, client *OpenidClient) (*OpenidClient, error) {
	var clientResponse OpenidClient

	body, err := gluuClient.post(ctx, "/clients", client)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &clientResponse)

	if err != nil {
		return nil, err
	}

	return &clientResponse, nil
}

func (gluuClient *GluuClient) GetOpenidClient(ctx context.Context, id string) (*OpenidClient, error) {
	var client OpenidClient
	var clientSecret OpenidClientSecret

	err := gluuClient.get(ctx, fmt.Sprintf("/clients/%s", id), &client, nil)
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
