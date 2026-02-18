#!/bin/bash

mkdir -p certs

# Create a temporary config file for SANs
cat > certs/openssl.conf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Dev
L = Local
O = Dev
CN = localhost

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = imap.yourdomain.com
DNS.3 = smtp.yourdomain.com
IP.1 = 127.0.0.1
EOF

openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -config certs/openssl.conf \
    -keyout certs/server.key -out certs/server.crt

rm certs/openssl.conf
