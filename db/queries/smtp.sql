-- name: GetDomainByName :one
SELECT id, name, smtp_domain, created_at FROM domains
WHERE name = $1;

-- name: GetAddressByNameAndDomain :one
SELECT id, name, domain, created_at FROM addresses
WHERE name = $1 AND domain = $2;

-- name: UserHasAccessToAddress :one
SELECT EXISTS (
    SELECT 1 FROM addresses a
    JOIN user_address ua ON a.id = ua.address_id
    WHERE a.id = $1 AND ua.user_id = $2
)::boolean;

-- name: GetAddressFromEmailAddress :one
SELECT a.*
FROM addresses a
JOIN domains d ON a.domain = d.id
WHERE
    a.name = split_part($1, '@', 1) AND
    d.name = split_part($1, '@', 2)
LIMIT 1;

-- name: CreateEmail :one
INSERT INTO emails (
    sender, recipients, body, spf_pass, dmarc_pass, dkim_pass
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING id;

-- name: AssociateEmailToMailbox :exec
INSERT INTO email_mailbox (email_id, mailbox_id, flags) VALUES ($1, $2, $3);

-- name: GetMailboxOfTypeForAddress :one
SELECT id, name, type, parent_id, address_id, created_at
FROM mailboxes
WHERE type = $1::mailbox_type AND address_id = $2;

-- name: EnqueueEmail :one
INSERT INTO email_queue (email_id) VALUES ($1) RETURNING id;

-- name: GetNextEmailFromQueue :one
SELECT eq.*, e.sender, e.recipients, e.body
FROM email_queue eq
JOIN emails e ON eq.email_id = e.id
WHERE (eq.status = 'pending' OR eq.status = 'failed')
  AND eq.next_attempt_at <= NOW()
ORDER BY eq.next_attempt_at ASC
LIMIT 1
FOR UPDATE SKIP LOCKED;

-- name: UpdateQueueStatus :exec
UPDATE email_queue
SET status = $2,
    retry_count = $3,
    last_attempt_at = NOW(),
    next_attempt_at = $4,
    last_error = $5
WHERE id = $1;

-- name: MarkEmailAsProcessing :exec
UPDATE email_queue
SET status = 'processing',
    last_attempt_at = NOW()
WHERE id = $1;

-- name: MarkEmailAsSent :exec
UPDATE email_queue
SET status = 'sent',
    last_attempt_at = NOW(),
    last_error = NULL
WHERE id = $1;