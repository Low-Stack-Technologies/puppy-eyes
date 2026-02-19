-- +migrate Up

-- +migrate StatementBegin
ALTER TABLE mailboxes
    ADD COLUMN uid_validity BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    ADD COLUMN uid_next BIGINT NOT NULL DEFAULT 1;
-- +migrate StatementEnd

-- +migrate StatementBegin
ALTER TABLE email_mailbox
    ADD COLUMN uid BIGINT;
-- +migrate StatementEnd

-- +migrate StatementBegin
UPDATE mailboxes
SET uid_validity = EXTRACT(EPOCH FROM created_at)::BIGINT
WHERE uid_validity IS NULL;
-- +migrate StatementEnd

-- +migrate StatementBegin
WITH ordered AS (
    SELECT em.email_id, em.mailbox_id,
           ROW_NUMBER() OVER (PARTITION BY em.mailbox_id ORDER BY e.created_at ASC) AS rn
    FROM email_mailbox em
    JOIN emails e ON e.id = em.email_id
)
UPDATE email_mailbox em
SET uid = ordered.rn
FROM ordered
WHERE em.email_id = ordered.email_id AND em.mailbox_id = ordered.mailbox_id;
-- +migrate StatementEnd

-- +migrate StatementBegin
UPDATE mailboxes m
SET uid_next = COALESCE((
    SELECT MAX(em.uid) + 1
    FROM email_mailbox em
    WHERE em.mailbox_id = m.id
), 1);
-- +migrate StatementEnd

-- +migrate StatementBegin
ALTER TABLE email_mailbox
    ALTER COLUMN uid SET NOT NULL;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE UNIQUE INDEX email_mailbox_mailbox_uid_idx ON email_mailbox (mailbox_id, uid);
-- +migrate StatementEnd

-- +migrate Down
DROP INDEX email_mailbox_mailbox_uid_idx;
ALTER TABLE email_mailbox DROP COLUMN uid;
ALTER TABLE mailboxes DROP COLUMN uid_next;
ALTER TABLE mailboxes DROP COLUMN uid_validity;
