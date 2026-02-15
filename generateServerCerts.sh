#!/bin/bash

mkdir -p certs
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout certs/server.key -out certs/server.crt \
    -subj "/C=US/ST=Dev/L=Local/O=Dev/CN=smtp.yourdomain.com"