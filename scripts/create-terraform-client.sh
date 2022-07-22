#!/usr/bin/env bash

GLUU_URL="https://no-idp.rstest.biz"
GLUU_USER="admin"
GLUU_PASSWORD="Rs-2019."
GLUU_CLIENT_ID="terraform"
GLUU_CLIENT_SECRET="884e0f95-0f42-4a63-9b1f-94274655669e"
CLIENT_CREDENTIALS=""

echo "Creating initial terraform client"

accessToken=$(
    curl -s -X POST --fail \
        -d "username=${GLUU_USER}" \
        -d "password=${GLUU_PASSWORD}" \
        -d "client_id=admin-cli" \
        -d "grant_type=password" \
        "${GLUU_URL}/jans-auth/restv1/token" \
        | jq -r '.access_token'
)

function post() {
    curl -X POST --fail \
        -H "Authorization: bearer ${accessToken}" \
        -H "Content-Type: application/json" \
        -d "${2}" \
        "${GLUU_URL}${1}"
}

function put() {
    curl --fail \
        -X PUT \
        -H "Authorization: bearer ${accessToken}" \
        -H "Content-Type: application/json" \
        -d "${2}" \
        "${GLUU_URL}${1}"
}

function get() {
    curl --fail --silent \
        -H "Authorization: bearer ${accessToken}" \
        -H "Content-Type: application/json" \
        "${GLUU_URL}${1}"
}

terraformClient=$(jq -n "{
    redirectUris: [ \"${GLUU_URL}" ]
}")

post "/jans-config-api/api/v1/openid/clients" "${terraformClient}"

echo "Done"
