-- +migrate Up

-- +migrate StatementBegin
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    smtp_domain TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    domain UUID REFERENCES domains(id),
    user_id UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE TABLE emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender TEXT NOT NULL,
    recipients TEXT[] NOT NULL,
    body TEXT NOT NULL,
    authenticated_user UUID REFERENCES users(id),
    spf_pass BOOLEAN,
    dmarc_pass BOOLEAN,
    dkim_pass BOOLEAN,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
INSERT INTO users (username, password) VALUES ('user', 'password');
-- +migrate StatementEnd

-- +migrate StatementBegin
INSERT INTO domains (name, smtp_domain) VALUES ('example.com', 'smtp.example.com');
-- +migrate StatementEnd

-- +migrate StatementBegin
INSERT INTO addresses (name, domain, user_id)
SELECT 'user', d.id, u.id
FROM domains d, users u
WHERE d.name = 'example.com' AND u.username = 'user';
-- +migrate StatementEnd

-- +migrate Down
DROP TABLE emails;
DROP TABLE addresses;
DROP TABLE domains;
DROP TABLE users;