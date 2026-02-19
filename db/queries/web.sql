-- name: GetUserByUsername :one
SELECT id, username, password, password_hash, is_admin, created_at
FROM users
WHERE username = $1;

-- name: GetUserByID :one
SELECT id, username, password, password_hash, is_admin, created_at
FROM users
WHERE id = $1;

-- name: SetUserPasswordHash :exec
UPDATE users
SET password_hash = $2
WHERE id = $1;

-- name: CreateWebSession :one
INSERT INTO web_sessions (user_id, active_address_id, expires_at)
VALUES ($1, $2, $3)
RETURNING id, user_id, active_address_id, expires_at, created_at, updated_at;

-- name: GetWebSession :one
SELECT ws.id, ws.user_id, ws.active_address_id, ws.expires_at, ws.created_at, ws.updated_at,
       u.username, u.is_admin
FROM web_sessions ws
JOIN users u ON u.id = ws.user_id
WHERE ws.id = $1 AND ws.expires_at > NOW();

-- name: ExtendWebSession :exec
UPDATE web_sessions
SET expires_at = $2, updated_at = NOW()
WHERE id = $1;

-- name: DeleteWebSession :exec
DELETE FROM web_sessions
WHERE id = $1;

-- name: DeleteExpiredWebSessions :exec
DELETE FROM web_sessions
WHERE expires_at <= NOW();

-- name: SetWebSessionActiveAddress :exec
UPDATE web_sessions
SET active_address_id = $2, updated_at = NOW()
WHERE id = $1;

-- name: GetUserAddresses :many
SELECT a.id, a.name, a.domain, a.created_at, d.name as domain_name
FROM addresses a
JOIN user_address ua ON ua.address_id = a.id
JOIN domains d ON d.id = a.domain
WHERE ua.user_id = $1
ORDER BY d.name ASC, a.name ASC;

-- name: UserCanAccessAddress :one
SELECT EXISTS (
    SELECT 1
    FROM user_address ua
    WHERE ua.user_id = $1 AND ua.address_id = $2
)::boolean;

-- name: GetMailboxByIDForAddress :one
SELECT id, name, type, parent_id, address_id, created_at, uid_validity, uid_next
FROM mailboxes
WHERE id = $1 AND address_id = $2;

-- name: GetAddressByID :one
SELECT id, name, domain, created_at
FROM addresses
WHERE id = $1;

-- name: GetDomainByID :one
SELECT id, name, smtp_domain, created_at
FROM domains
WHERE id = $1;

-- name: ListMailboxesByAddressForUser :many
SELECT m.id, m.name, m.type, m.parent_id, m.address_id, m.created_at, m.uid_validity, m.uid_next
FROM mailboxes m
JOIN user_address ua ON ua.address_id = m.address_id
WHERE ua.user_id = $1 AND m.address_id = $2
ORDER BY m.type NULLS LAST, m.name ASC;

-- name: ListMailboxMessagesPage :many
SELECT em.mailbox_id, em.uid, em.flags,
       e.id, e.sender, e.recipients, e.body, e.created_at
FROM email_mailbox em
JOIN emails e ON e.id = em.email_id
WHERE em.mailbox_id = $1
  AND ($2::bigint = 0 OR em.uid < $2)
ORDER BY em.uid DESC
LIMIT $3;

-- name: GetMailboxMessageByEmailID :one
SELECT em.mailbox_id, em.uid, em.flags,
       e.id, e.sender, e.recipients, e.body, e.created_at
FROM email_mailbox em
JOIN emails e ON e.id = em.email_id
WHERE em.mailbox_id = $1 AND e.id = $2;

-- name: CountMessagesInMailbox :one
SELECT count(*)::bigint
FROM email_mailbox
WHERE mailbox_id = $1;

-- name: GetMessageFlagsByEmailInMailbox :one
SELECT flags
FROM email_mailbox
WHERE mailbox_id = $1 AND email_id = $2;

-- name: CreateUserWithPasswordHash :one
INSERT INTO users (username, password, password_hash, is_admin)
VALUES ($1, '', $2, $3)
RETURNING id, username, password, password_hash, is_admin, created_at;

-- name: ListUsers :many
SELECT id, username, password, password_hash, is_admin, created_at
FROM users
ORDER BY username ASC;

-- name: UpdateUserBasics :one
UPDATE users
SET username = $2, is_admin = $3
WHERE id = $1
RETURNING id, username, password, password_hash, is_admin, created_at;

-- name: DeleteUserByID :exec
DELETE FROM users
WHERE id = $1;

-- name: UpdateUserPasswordHash :exec
UPDATE users
SET password_hash = $2
WHERE id = $1;

-- name: CreateDomain :one
INSERT INTO domains (name, smtp_domain)
VALUES ($1, $2)
RETURNING id, name, smtp_domain, created_at;

-- name: ListDomains :many
SELECT id, name, smtp_domain, created_at
FROM domains
ORDER BY name ASC;

-- name: UpdateDomain :one
UPDATE domains
SET name = $2, smtp_domain = $3
WHERE id = $1
RETURNING id, name, smtp_domain, created_at;

-- name: DeleteDomainByID :exec
DELETE FROM domains
WHERE id = $1;

-- name: CreateAddress :one
INSERT INTO addresses (name, domain)
VALUES ($1, $2)
RETURNING id, name, domain, created_at;

-- name: ListAddressesScopedByUser :many
SELECT a.id, a.name, a.domain, a.created_at, d.name as domain_name
FROM addresses a
JOIN domains d ON d.id = a.domain
JOIN user_address ua ON ua.address_id = a.id
WHERE ua.user_id = $1
ORDER BY d.name ASC, a.name ASC;

-- name: ListAddressesGlobal :many
SELECT a.id, a.name, a.domain, a.created_at, d.name as domain_name
FROM addresses a
JOIN domains d ON d.id = a.domain
ORDER BY d.name ASC, a.name ASC;

-- name: UpdateAddress :one
UPDATE addresses
SET name = $2, domain = $3
WHERE id = $1
RETURNING id, name, domain, created_at;

-- name: DeleteAddressByID :exec
DELETE FROM addresses
WHERE id = $1;

-- name: CreateUserAddressAccess :exec
INSERT INTO user_address (user_id, address_id)
VALUES ($1, $2)
ON CONFLICT (user_id, address_id) DO NOTHING;

-- name: DeleteUserAddressAccess :exec
DELETE FROM user_address
WHERE user_id = $1 AND address_id = $2;

-- name: ListUserAddressAccessScopedByUser :many
SELECT ua.user_id, ua.address_id, u.username, a.name as address_name, d.name as domain_name
FROM user_address ua
JOIN users u ON u.id = ua.user_id
JOIN addresses a ON a.id = ua.address_id
JOIN domains d ON d.id = a.domain
WHERE ua.address_id IN (
    SELECT ua2.address_id FROM user_address ua2 WHERE ua2.user_id = $1
)
ORDER BY u.username ASC, d.name ASC, a.name ASC;

-- name: ListUserAddressAccessGlobal :many
SELECT ua.user_id, ua.address_id, u.username, a.name as address_name, d.name as domain_name
FROM user_address ua
JOIN users u ON u.id = ua.user_id
JOIN addresses a ON a.id = ua.address_id
JOIN domains d ON d.id = a.domain
ORDER BY u.username ASC, d.name ASC, a.name ASC;

-- name: ListMailboxesScopedByUser :many
SELECT m.id, m.name, m.type, m.parent_id, m.address_id, m.created_at, m.uid_validity, m.uid_next,
       a.name as address_name, d.name as domain_name
FROM mailboxes m
JOIN addresses a ON a.id = m.address_id
JOIN domains d ON d.id = a.domain
JOIN user_address ua ON ua.address_id = m.address_id
WHERE ua.user_id = $1
ORDER BY d.name ASC, a.name ASC, m.name ASC;

-- name: ListMailboxesGlobal :many
SELECT m.id, m.name, m.type, m.parent_id, m.address_id, m.created_at, m.uid_validity, m.uid_next,
       a.name as address_name, d.name as domain_name
FROM mailboxes m
JOIN addresses a ON a.id = m.address_id
JOIN domains d ON d.id = a.domain
ORDER BY d.name ASC, a.name ASC, m.name ASC;

-- name: CreateMailboxFull :one
INSERT INTO mailboxes (name, type, parent_id, address_id)
VALUES ($1, $2, $3, $4)
RETURNING id, name, type, parent_id, address_id, created_at, uid_validity, uid_next;

-- name: UpdateMailbox :one
UPDATE mailboxes
SET name = $2, type = $3, parent_id = $4
WHERE id = $1
RETURNING id, name, type, parent_id, address_id, created_at, uid_validity, uid_next;

-- name: DeleteMailboxByID :exec
DELETE FROM mailboxes
WHERE id = $1;

-- name: DeleteEmailMailboxByMailboxID :exec
DELETE FROM email_mailbox
WHERE mailbox_id = $1;

-- name: DeleteMailboxesByAddressID :exec
DELETE FROM mailboxes
WHERE address_id = $1;

-- name: DeleteUserAddressByAddressID :exec
DELETE FROM user_address
WHERE address_id = $1;

-- name: DeleteAddressesByDomainID :exec
DELETE FROM addresses
WHERE domain = $1;
