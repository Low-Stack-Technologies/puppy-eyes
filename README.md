# Puppy Eyes

The goal of this project is to make an easy to set up and use email server. It should primarily support eSMTP and IMAP4. It will use a PostgreSQL database for storage, and be build in Golang.

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

The TXT value should include your public key (without PEM headers/footers and without whitespace):

```
v=DKIM1; k=rsa; p=<BASE64_PUBLIC_KEY>
```

To extract the base64 public key:

```bash
openssl rsa -in dkim_private.pem -pubout -outform pem | \
  sed '1d;$d' | tr -d '\n'
```

Once DNS is published, outgoing mail signed by this server should pass DKIM validation.
