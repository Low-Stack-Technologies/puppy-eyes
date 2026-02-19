-- +migrate Up

-- +migrate StatementBegin
ALTER TABLE users
    ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN password_hash TEXT;
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE UNIQUE INDEX users_username_unique_idx ON users (username);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE UNIQUE INDEX domains_name_unique_idx ON domains (name);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE UNIQUE INDEX addresses_name_domain_unique_idx ON addresses (name, domain);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE web_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    active_address_id UUID REFERENCES addresses(id) ON DELETE SET NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE INDEX web_sessions_user_id_idx ON web_sessions (user_id);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE INDEX web_sessions_expires_at_idx ON web_sessions (expires_at);
-- +migrate StatementEnd

-- +migrate Down
DROP INDEX web_sessions_expires_at_idx;
DROP INDEX web_sessions_user_id_idx;
DROP TABLE web_sessions;
DROP INDEX addresses_name_domain_unique_idx;
DROP INDEX domains_name_unique_idx;
DROP INDEX users_username_unique_idx;
ALTER TABLE users DROP COLUMN password_hash;
ALTER TABLE users DROP COLUMN is_admin;
