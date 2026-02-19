-- +migrate Up

-- +migrate StatementBegin
CREATE TABLE dmarc_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    header_from_domain TEXT NOT NULL,
    policy_domain TEXT NOT NULL,
    used_org_fallback BOOLEAN NOT NULL DEFAULT FALSE,
    source_ip TEXT NOT NULL,
    spf_result TEXT NOT NULL,
    spf_domain TEXT NOT NULL,
    dkim_domains TEXT[],
    spf_aligned BOOLEAN NOT NULL,
    dkim_aligned BOOLEAN NOT NULL,
    dmarc_pass BOOLEAN NOT NULL,
    disposition TEXT NOT NULL,
    policy_p TEXT NOT NULL,
    policy_sp TEXT,
    policy_adkim TEXT NOT NULL,
    policy_aspf TEXT NOT NULL,
    policy_pct INT NOT NULL,
    policy_rua TEXT[],
    policy_ruf TEXT[],
    policy_fo TEXT,
    policy_ri INT NOT NULL
);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE INDEX dmarc_events_policy_domain_created_at_idx ON dmarc_events (policy_domain, created_at);
-- +migrate StatementEnd

-- +migrate StatementBegin
CREATE INDEX dmarc_events_created_at_idx ON dmarc_events (created_at);
-- +migrate StatementEnd

-- +migrate Down
DROP TABLE dmarc_events;
