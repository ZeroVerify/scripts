#!/bin/bash
set -euo pipefail

KEYCLOAK="https://keycloak.zeroverify.net"
REALM="zeroverify"
CLIENT_ID="zeroverify-wallet"
REDIRECT_URI="https://wallet.zeroverify.net/callback"
IDP_HINT="mock-idp"

# Generate PKCE pair via Python3 (reliable cross-platform)
read -r verifier challenge < <(python3 -c "
import base64, hashlib, os
v = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
print(v, c)
")

echo ""
echo "=== Step 1: Log OUT any active Keycloak session first ==="
echo ""
echo "${KEYCLOAK}/realms/${REALM}/protocol/openid-connect/logout?client_id=${CLIENT_ID}&post_logout_redirect_uri=${REDIRECT_URI}"
echo ""
read -rp "Press Enter once logged out (or if no session was active)..."

echo ""
echo "=== Step 2: Open the login URL ==="
echo ""
echo "${KEYCLOAK}/realms/${REALM}/protocol/openid-connect/auth?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=openid&code_challenge=${challenge}&code_challenge_method=S256&kc_idp_hint=${IDP_HINT}"
echo ""
echo "Log in with:  testuser / password"
echo ""
echo "=== Step 3: Paste the full callback URL ==="
echo ""
read -rp "Paste here: " input

# Extract code from either a full URL or raw code value
if [[ "$input" == http* ]]; then
  code=$(echo "$input" | grep -oP '(?<=code=)[^&]+')
else
  code="$input"
fi

echo ""
echo "=== Exchanging code for tokens... ==="
echo ""

response=$(curl -s -X POST "${KEYCLOAK}/realms/${REALM}/protocol/openid-connect/token" \
  -d grant_type=authorization_code \
  -d client_id="${CLIENT_ID}" \
  -d redirect_uri="${REDIRECT_URI}" \
  -d code="${code}" \
  -d code_verifier="${verifier}")

if echo "$response" | jq -e '.error' > /dev/null 2>&1; then
  echo "Token exchange failed:"
  echo "$response" | jq .
  exit 1
fi

id_token=$(echo "$response" | jq -r '.id_token')

echo "=== ID Token Claims ==="
echo ""
echo "$id_token" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
