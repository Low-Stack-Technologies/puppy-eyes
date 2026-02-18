-- +migrate Up

-- +migrate StatementBegin
CREATE TABLE domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    smtp_domain TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    domain UUID REFERENCES domains(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE user_address (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    address_id UUID REFERENCES addresses(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, address_id)
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TYPE mailbox_type AS ENUM ('INBOX', 'DRAFTS', 'SENT', 'TRASH', 'SPAM', 'ARCHIVE');
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE mailboxes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    type mailbox_type,
    parent_id UUID REFERENCES mailboxes(id), -- If NULL, its in the root
    address_id UUID REFERENCES addresses(id) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE (name, parent_id),
    UNIQUE (address_id, type)
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender TEXT NOT NULL,
    recipients TEXT[] NOT NULL,
    body TEXT NOT NULL,
    spf_pass BOOLEAN,
    dmarc_pass BOOLEAN,
    dkim_pass BOOLEAN,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE email_mailbox (
    email_id UUID REFERENCES emails(id) ON DELETE CASCADE,
    mailbox_id UUID REFERENCES mailboxes(id) ON DELETE CASCADE,
    flags TEXT[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (email_id, mailbox_id)
);
-- +migrate StatementEnd

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
DROP TABLE email_queue;
DROP TYPE email_status;
DROP TABLE email_mailbox;
DROP TABLE emails;
DROP TABLE mailboxes;
DROP TYPE mailbox_type;
DROP TABLE user_address;
DROP TABLE addresses;
DROP TABLE users;
DROP TABLE domains;