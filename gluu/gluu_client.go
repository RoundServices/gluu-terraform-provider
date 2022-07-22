package gluu

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-version"

	"golang.org/x/net/publicsuffix"

	"github.com/hashicorp/go-retryablehttp"
)

type GluuClient struct {
	baseUrl           string
	realm             string
	clientCredentials *ClientCredentials
	httpClient        *http.Client
	initialLogin      bool
	userAgent         string
	version           *version.Version
	additionalHeaders map[string]string
	debug             bool
}

type ClientCredentials struct {
	ClientId     string
	ClientSecret string
	Username     string
	Password     string
	GrantType    string
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

const (
	apiUrl   = ""
	tokenUrl = "/jans-auth/restv1/token"
)

func NewGluuClient(ctx context.Context, url, basePath, clientId, clientSecret, realm, username, password string, initialLogin bool, clientTimeout int, caCert string, tlsInsecureSkipVerify bool, userAgent string, additionalHeaders map[string]string) (*GluuClient, error) {
	clientCredentials := &ClientCredentials{
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}
	if password != "" && username != "" {
		clientCredentials.Username = username
		clientCredentials.Password = password
		clientCredentials.GrantType = "password"
	} else if clientSecret != "" {
		clientCredentials.GrantType = "client_credentials"
	} else {
		if initialLogin {
			return nil, fmt.Errorf("must specify client id, username and password for password grant, or client id and secret for client credentials grant")
		} else {
			tflog.Warn(ctx, "missing required gluu credentials, but proceeding anyways as initial_login is false")
		}
	}

	httpClient, err := newHttpClient(tlsInsecureSkipVerify, clientTimeout, caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to create http client: %v", err)
	}

	gluuClient := GluuClient{
		baseUrl:           url + basePath,
		clientCredentials: clientCredentials,
		httpClient:        httpClient,
		initialLogin:      initialLogin,
		realm:             realm,
		userAgent:         userAgent,
		additionalHeaders: additionalHeaders,
	}

	if gluuClient.initialLogin {
		err = gluuClient.login(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to perform initial login to Gluu: %v", err)
		}
	}

	if tfLog, ok := os.LookupEnv("TF_LOG"); ok {
		if tfLog == "DEBUG" {
			gluuClient.debug = true
		}
	}

	return &gluuClient, nil
}

func (gluuClient *GluuClient) login(ctx context.Context) error {
	accessTokenUrl := fmt.Sprintf(tokenUrl, gluuClient.baseUrl, gluuClient.realm)
	accessTokenData := gluuClient.getAuthenticationFormData()

	tflog.Debug(ctx, "Login request", map[string]interface{}{
		"request": accessTokenData.Encode(),
	})

	accessTokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, accessTokenUrl, strings.NewReader(accessTokenData.Encode()))
	if err != nil {
		return err
	}

	for header, value := range gluuClient.additionalHeaders {
		accessTokenRequest.Header.Set(header, value)
	}

	accessTokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if gluuClient.userAgent != "" {
		accessTokenRequest.Header.Set("User-Agent", gluuClient.userAgent)
	}

	accessTokenResponse, err := gluuClient.httpClient.Do(accessTokenRequest)
	if err != nil {
		return err
	}
	if accessTokenResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("error sending POST request to %s: %s", accessTokenUrl, accessTokenResponse.Status)
	}

	defer accessTokenResponse.Body.Close()

	body, _ := ioutil.ReadAll(accessTokenResponse.Body)

	tflog.Debug(ctx, "Login response", map[string]interface{}{
		"response": string(body),
	})

	var clientCredentials ClientCredentials
	err = json.Unmarshal(body, &clientCredentials)
	if err != nil {
		return err
	}

	gluuClient.clientCredentials.AccessToken = clientCredentials.AccessToken
	gluuClient.clientCredentials.RefreshToken = clientCredentials.RefreshToken
	gluuClient.clientCredentials.TokenType = clientCredentials.TokenType

	return nil
}

func (gluuClient *GluuClient) refresh(ctx context.Context) error {
	refreshTokenUrl := fmt.Sprintf(tokenUrl, gluuClient.baseUrl, gluuClient.realm)
	refreshTokenData := gluuClient.getAuthenticationFormData()

	tflog.Debug(ctx, "Refresh request", map[string]interface{}{
		"request": refreshTokenData.Encode(),
	})

	refreshTokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, refreshTokenUrl, strings.NewReader(refreshTokenData.Encode()))
	if err != nil {
		return err
	}

	for header, value := range gluuClient.additionalHeaders {
		refreshTokenRequest.Header.Set(header, value)
	}

	refreshTokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if gluuClient.userAgent != "" {
		refreshTokenRequest.Header.Set("User-Agent", gluuClient.userAgent)
	}

	refreshTokenResponse, err := gluuClient.httpClient.Do(refreshTokenRequest)
	if err != nil {
		return err
	}

	defer refreshTokenResponse.Body.Close()

	body, _ := ioutil.ReadAll(refreshTokenResponse.Body)

	tflog.Debug(ctx, "Refresh response", map[string]interface{}{
		"response": string(body),
	})

	// Handle 401 "User or client no longer has role permissions for client key" until I better understand why that happens in the first place
	if refreshTokenResponse.StatusCode == http.StatusBadRequest {
		tflog.Debug(ctx, "Unexpected 400, attempting to log in again")

		return gluuClient.login(ctx)
	}

	var clientCredentials ClientCredentials
	err = json.Unmarshal(body, &clientCredentials)
	if err != nil {
		return err
	}

	gluuClient.clientCredentials.AccessToken = clientCredentials.AccessToken
	gluuClient.clientCredentials.RefreshToken = clientCredentials.RefreshToken
	gluuClient.clientCredentials.TokenType = clientCredentials.TokenType

	return nil
}

func (gluuClient *GluuClient) getAuthenticationFormData() url.Values {
	authenticationFormData := url.Values{}
	authenticationFormData.Set("client_id", gluuClient.clientCredentials.ClientId)
	authenticationFormData.Set("grant_type", gluuClient.clientCredentials.GrantType)

	if gluuClient.clientCredentials.GrantType == "password" {
		authenticationFormData.Set("username", gluuClient.clientCredentials.Username)
		authenticationFormData.Set("password", gluuClient.clientCredentials.Password)

		if gluuClient.clientCredentials.ClientSecret != "" {
			authenticationFormData.Set("client_secret", gluuClient.clientCredentials.ClientSecret)
		}

	} else if gluuClient.clientCredentials.GrantType == "client_credentials" {
		authenticationFormData.Set("client_secret", gluuClient.clientCredentials.ClientSecret)
	}

	return authenticationFormData
}

func (gluuClient *GluuClient) addRequestHeaders(request *http.Request) {
	tokenType := gluuClient.clientCredentials.TokenType
	accessToken := gluuClient.clientCredentials.AccessToken

	for header, value := range gluuClient.additionalHeaders {
		request.Header.Set(header, value)
	}

	request.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken))
	request.Header.Set("Accept", "application/json")

	if gluuClient.userAgent != "" {
		request.Header.Set("User-Agent", gluuClient.userAgent)
	}

	if request.Method == http.MethodPost || request.Method == http.MethodPut || request.Method == http.MethodDelete {
		request.Header.Set("Content-type", "application/json")
	}
}

/**
Sends an HTTP request and refreshes credentials on 403 or 401 errors
*/
func (gluuClient *GluuClient) sendRequest(ctx context.Context, request *http.Request, body []byte) ([]byte, string, error) {
	if !gluuClient.initialLogin {
		gluuClient.initialLogin = true
		err := gluuClient.login(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("error logging in: %s", err)
		}
	}

	requestMethod := request.Method
	requestPath := request.URL.Path

	requestLogArgs := map[string]interface{}{
		"method": requestMethod,
		"path":   requestPath,
	}

	if body != nil {
		request.Body = ioutil.NopCloser(bytes.NewReader(body))
		requestLogArgs["body"] = string(body)
	}

	tflog.Debug(ctx, "Sending request", requestLogArgs)

	gluuClient.addRequestHeaders(request)

	response, err := gluuClient.httpClient.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("error sending request: %v", err)
	}

	// Unauthorized: Token could have expired
	// Forbidden: After creating a realm, following GETs for the realm return 403 until you refresh
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		tflog.Debug(ctx, "Got unexpected response, attempting refresh", map[string]interface{}{
			"status": response.Status,
		})

		err := gluuClient.refresh(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("error refreshing credentials: %s", err)
		}

		gluuClient.addRequestHeaders(request)

		if body != nil {
			request.Body = ioutil.NopCloser(bytes.NewReader(body))
		}
		response, err = gluuClient.httpClient.Do(request)
		if err != nil {
			return nil, "", fmt.Errorf("error sending request after refresh: %v", err)
		}
	}

	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, "", err
	}

	responseLogArgs := map[string]interface{}{
		"status": response.Status,
	}

	if len(responseBody) != 0 && request.URL.Path != "/auth/admin/serverinfo" {
		responseLogArgs["body"] = string(responseBody)
	}

	tflog.Debug(ctx, "Received response", responseLogArgs)

	if response.StatusCode >= 400 {
		errorMessage := fmt.Sprintf("error sending %s request to %s: %s.", request.Method, request.URL.Path, response.Status)

		if len(responseBody) != 0 {
			errorMessage = fmt.Sprintf("%s Response body: %s", errorMessage, responseBody)
		}

		return nil, "", &ApiError{
			Code:    response.StatusCode,
			Message: errorMessage,
		}
	}

	return responseBody, response.Header.Get("Location"), nil
}

func (gluuClient *GluuClient) get(ctx context.Context, path string, resource interface{}, params map[string]string) error {
	body, err := gluuClient.getRaw(ctx, path, params)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, resource)
}

func (gluuClient *GluuClient) getRaw(ctx context.Context, path string, params map[string]string) ([]byte, error) {
	resourceUrl := gluuClient.baseUrl + apiUrl + path

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceUrl, nil)
	if err != nil {
		return nil, err
	}

	if params != nil {
		query := url.Values{}
		for k, v := range params {
			query.Add(k, v)
		}
		request.URL.RawQuery = query.Encode()
	}

	body, _, err := gluuClient.sendRequest(ctx, request, nil)
	return body, err
}

func (gluuClient *GluuClient) sendRaw(ctx context.Context, path string, requestBody []byte) ([]byte, error) {
	resourceUrl := gluuClient.baseUrl + apiUrl + path

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceUrl, nil)
	if err != nil {
		return nil, err
	}

	body, _, err := gluuClient.sendRequest(ctx, request, requestBody)

	return body, err
}

func (gluuClient *GluuClient) post(ctx context.Context, path string, requestBody interface{}) ([]byte, string, error) {
	resourceUrl := gluuClient.baseUrl + apiUrl + path

	payload, err := gluuClient.marshal(requestBody)
	if err != nil {
		return nil, "", err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceUrl, nil)
	if err != nil {
		return nil, "", err
	}

	body, location, err := gluuClient.sendRequest(ctx, request, payload)

	return body, location, err
}

func (gluuClient *GluuClient) put(ctx context.Context, path string, requestBody interface{}) error {
	resourceUrl := gluuClient.baseUrl + apiUrl + path

	payload, err := gluuClient.marshal(requestBody)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPut, resourceUrl, nil)
	if err != nil {
		return err
	}

	_, _, err = gluuClient.sendRequest(ctx, request, payload)

	return err
}

func (gluuClient *GluuClient) delete(ctx context.Context, path string, requestBody interface{}) error {
	resourceUrl := gluuClient.baseUrl + apiUrl + path

	var (
		payload []byte
		err     error
	)

	if requestBody != nil {
		payload, err = gluuClient.marshal(requestBody)
		if err != nil {
			return err
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, resourceUrl, nil)
	if err != nil {
		return err
	}

	_, _, err = gluuClient.sendRequest(ctx, request, payload)

	return err
}

func (gluuClient *GluuClient) marshal(body interface{}) ([]byte, error) {
	if gluuClient.debug {
		return json.MarshalIndent(body, "", "    ")
	}

	return json.Marshal(body)
}

func newHttpClient(tlsInsecureSkipVerify bool, clientTimeout int, caCert string) (*http.Client, error) {
	cookieJar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsInsecureSkipVerify},
		Proxy:           http.ProxyFromEnvironment,
	}

	if caCert != "" {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(caCert))
		transport.TLSClientConfig.RootCAs = caCertPool
	}

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 1
	retryClient.RetryWaitMin = time.Second * 1
	retryClient.RetryWaitMax = time.Second * 3

	httpClient := retryClient.StandardClient()
	httpClient.Timeout = time.Second * time.Duration(clientTimeout)
	httpClient.Transport = transport
	httpClient.Jar = cookieJar

	return httpClient, nil
}
