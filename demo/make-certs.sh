#!/bin/sh
# Makes the demo CA and the Keycloak server certificate. Demo only: never use these anywhere real.
# Usage: make-certs.sh [dir]   (default: the certs/ folder next to this script)
# Idempotent: does nothing when the files already exist. Delete the folder's contents to start over.
set -eu

dir=${1:-$(dirname "$0")/certs}
mkdir -p "$dir"
cd "$dir"

if [ -s ca.crt ] && [ -s keycloak.crt ] && [ -s keycloak.key ]; then
    echo "certs: already present in $dir"
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 \
    -subj "/CN=pg-oauth-rs demo CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout ca.key -out ca.crt

openssl req -newkey rsa:2048 -nodes -subj "/CN=keycloak.localtest.me" \
    -keyout keycloak.key -out keycloak.csr

cat > keycloak.ext <<'EOF'
subjectAltName = DNS:keycloak.localtest.me, DNS:keycloak, DNS:localhost
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

# 825 days: the longest validity macOS and iOS accept for a TLS server certificate.
openssl x509 -req -sha256 -days 825 -in keycloak.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -extfile keycloak.ext -out keycloak.crt

rm -f keycloak.csr keycloak.ext ca.srl
chmod 600 ca.key
# Keycloak runs as uid 1000 and must read its key from this bind mount. Demo only.
chmod 644 ca.crt keycloak.crt keycloak.key
echo "certs: wrote ca.crt, keycloak.crt, keycloak.key to $dir"
