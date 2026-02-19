-- name: CreateMailbox :exec
INSERT INTO mailboxes (name, address_id)
VALUES ($1, $2);

-- name: UpdateEmailFlags :exec
UPDATE email_mailbox
SET flags = $3
WHERE email_id = $1 AND mailbox_id = $2;

-- name: AllocateMailboxUID :one
UPDATE mailboxes
SET uid_next = uid_next + 1
WHERE id = $1
RETURNING uid_next - 1 AS uid;

-- name: DeleteEmailFromMailbox :exec
DELETE FROM email_mailbox
WHERE email_id = $1 AND mailbox_id = $2;

-- name: DeleteOrphanEmails :exec
DELETE FROM emails e
WHERE NOT EXISTS (
    SELECT 1 FROM email_mailbox em WHERE em.email_id = e.id
);

-- name: GetAddressIDForUser :one
SELECT address_id FROM user_address WHERE user_id = $1 LIMIT 1;

-- name: GetUserMailboxes :many
SELECT m.id, m.name, m.type, m.parent_id
FROM mailboxes m
JOIN user_address ua ON m.address_id = ua.address_id
WHERE ua.user_id = $1;

-- name: GetMailboxByNameForUser :one
SELECT m.id, m.name, m.type, m.parent_id, m.uid_validity, m.uid_next
FROM mailboxes m
JOIN user_address ua ON m.address_id = ua.address_id
WHERE ua.user_id = $1 AND m.name = $2;

-- name: GetEmailsInMailbox :many
SELECT e.id, e.sender, e.recipients, e.body, e.created_at, em.flags, em.uid
FROM emails e
JOIN email_mailbox em ON e.id = em.email_id
WHERE em.mailbox_id = $1
ORDER BY em.uid ASC;

-- name: GetEmailByID :one
SELECT id, sender, recipients, body, created_at
FROM emails
WHERE id = $1;
