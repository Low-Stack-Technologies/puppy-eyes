-- name: CreateMailbox :exec
INSERT INTO mailboxes (name, address_id)
VALUES ($1, $2);

-- name: GetAddressIDForUser :one
SELECT address_id FROM user_address WHERE user_id = $1 LIMIT 1;

-- name: GetUserMailboxes :many
SELECT m.id, m.name, m.type, m.parent_id
FROM mailboxes m
JOIN user_address ua ON m.address_id = ua.address_id
WHERE ua.user_id = $1;

-- name: GetMailboxByNameForUser :one
SELECT m.id, m.name, m.type, m.parent_id
FROM mailboxes m
JOIN user_address ua ON m.address_id = ua.address_id
WHERE ua.user_id = $1 AND m.name = $2;

-- name: GetEmailsInMailbox :many
SELECT e.id, e.sender, e.recipients, e.body, e.created_at
FROM emails e
JOIN email_mailbox em ON e.id = em.email_id
WHERE em.mailbox_id = $1
ORDER BY e.created_at ASC;

-- name: GetEmailByID :one
SELECT id, sender, recipients, body, created_at
FROM emails
WHERE id = $1;
