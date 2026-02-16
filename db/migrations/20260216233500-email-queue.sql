-- +migrate Up
-- +migrate StatementBegin
CREATE TYPE email_status AS ENUM ('pending', 'processing', 'sent', 'failed');
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE email_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id UUID NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    status email_status NOT NULL DEFAULT 'pending',
    retry_count INT NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMP WITH TIME ZONE,
    next_attempt_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate Down
-- +migrate StatementBegin
DROP TABLE email_queue;
-- +migrate StatementEnd
-- +migrate StatementBegin
DROP TYPE email_status;
-- +migrate StatementEnd
