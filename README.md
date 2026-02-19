# Puppy Eyes

The goal of this project is to make an easy to set up and use email server. It should primarily support eSMTP and IMAP4. It will use a PostgreSQL database for storage, and be build in Golang.

## TLS Certificates

The server supports STARTTLS and implicit TLS for SMTP and IMAP. Configure the certificate and key using these environment variables:

- `TLS_CERT_PATH`: path to the PEM certificate (default: `certs/tls/server.crt`).
- `TLS_KEY_PATH`: path to the PEM private key (default: `certs/tls/server.key`).

### Ports and TLS behavior

- SMTP `25`: STARTTLS (server-to-server).
- SMTP `587`: STARTTLS (client submission).
- SMTP `465`: implicit TLS.
- IMAP `143`: STARTTLS.
- IMAP `993`: implicit TLS.

### Get a certificate with certbot (DNS-01)

The DNS-01 challenge works even when ports 80/443 are blocked. Example:

```bash
sudo certbot certonly --manual --preferred-challenges dns \
  -d mail.example.com -d smtp.example.com -d imap.example.com
```

Certbot will prompt you to create one or more `_acme-challenge` TXT records. Once validation completes, your files are typically at:

- `/etc/letsencrypt/live/<your-domain>/fullchain.pem`
- `/etc/letsencrypt/live/<your-domain>/privkey.pem`

Point the server to those files:

```bash
export TLS_CERT_PATH=/etc/letsencrypt/live/<your-domain>/fullchain.pem
export TLS_KEY_PATH=/etc/letsencrypt/live/<your-domain>/privkey.pem
```

Make sure the process running the server can read the certificate and key files.

## DKIM Signing

Outbound mail is signed with DKIM before it is queued. Configure DKIM with these environment variables:

- `DKIM_KEY_PATH`: path to the PEM private key used for signing (default: `certs/dkim/dkim_private.pem`).
- `DKIM_SELECTOR`: selector used in DNS (default: `default`).
- `DKIM_HEADER_KEYS`: comma-separated list of headers to sign (default: `From,To,Subject,Date,Message-ID`).

### Generate a DKIM key

Example (RSA 2048):

```bash
openssl genrsa -out dkim_private.pem 2048
openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem
```

### Publish the DNS record

Create a TXT record at:

```
<selector>._domainkey.<your-domain>
```

Example with the default selector:

```
default._domainkey.example.com
```

The selector comes from `DKIM_SELECTOR`. If you don’t set it, the server uses `default`. The domain part is the sender’s domain (the part after `@` in the envelope sender).

The TXT value should include your public key (without PEM headers/footers and without whitespace):

```
v=DKIM1; k=rsa; p=<BASE64_PUBLIC_KEY>
```

DNS record example:

| Type | Name                           | TTL  | Content                                      |
|------|--------------------------------|------|----------------------------------------------|
| TXT  | default._domainkey.example.com | 3600 | v=DKIM1; k=rsa; p=&lt;BASE64_PUBLIC_KEY&gt; |

To extract the base64 public key:

```bash
openssl rsa -in dkim_private.pem -pubout -outform pem | \
  sed '1d;$d' | tr -d '\n'
```

Once DNS is published, outgoing mail signed by this server should pass DKIM validation.
