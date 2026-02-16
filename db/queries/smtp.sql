-- name: GetDomainByName :one
SELECT id, name, smtp_domain, created_at FROM domains
WHERE name = $1;

-- name: GetAddressByNameAndDomain :one
SELECT id, name, domain, user_id, created_at FROM addresses
WHERE name = $1 AND domain = $2;

-- name: CreateEmail :one
INSERT INTO emails (
    sender, recipients, body, authenticated_user, spf_pass, dmarc_pass, dkim_pass
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING id;
