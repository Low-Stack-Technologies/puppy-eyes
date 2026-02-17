-- +migrate Up

-- +migrate StatementBegin
INSERT INTO users (username, password) VALUES ('user', 'password');
-- +migrate StatementEnd

-- +migrate StatementBegin
INSERT INTO domains (name, smtp_domain) VALUES ('example.com', 'smtp.example.com');
-- +migrate StatementEnd

-- +migrate StatementBegin
INSERT INTO addresses (name, domain)
SELECT 'user', d.id
FROM domains d
WHERE d.name = 'example.com';
-- +migrate StatementEnd

-- +migrate StatementBegin
INSERT INTO user_address (user_id, address_id)
SELECT u.id, a.id
FROM users u, addresses a
WHERE u.username = 'user' AND a.name = 'user';
-- +migrate StatementEnd

-- +migrate StatementBegin
INSERT INTO mailboxes (name, type, address_id)
SELECT m.name, m.name::mailbox_type, a.id
FROM addresses a
CROSS JOIN (VALUES ('INBOX'), ('DRAFTS'), ('SENT'), ('TRASH'), ('SPAM'), ('ARCHIVE')) AS m(name)
WHERE a.name = 'user';
-- +migrate StatementEnd

-- +migrate Down
DELETE FROM mailboxes WHERE name IN ('INBOX', 'DRAFTS', 'SENT', 'TRASH', 'SPAM', 'ARCHIVE');
DELETE FROM addresses WHERE name = 'user';
DELETE FROM domains WHERE name = 'example.com';
DELETE FROM users WHERE username = 'user';