#!/bin/bash
# scripts/generate_mtls_certs.sh
mkdir -p certs
cd certs

echo "1. Generating Certificate Authority (CA)..."
openssl req -new -x509 -days 365 -nodes -keyout ca.key -out ca.crt -subj "/CN=koot-root-ca"

echo "2. Generating Server Certificate..."
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

echo "3. Generating Authorized Client Certificate..."
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=koot-authorized-client-01"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

echo "4. Generating Unauthorized Client Certificate (Different CA)..."
openssl req -new -x509 -days 365 -nodes -keyout rogue_ca.key -out rogue_ca.crt -subj "/CN=rogue-ca"
openssl req -newkey rsa:2048 -nodes -keyout rogue_client.key -out rogue_client.csr -subj "/CN=rogue-client"
openssl x509 -req -days 365 -in rogue_client.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial -out rogue_client.crt

echo "Certificates generated successfully in ./certs/"