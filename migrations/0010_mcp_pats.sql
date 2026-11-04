-- Personal access tokens for MCP (scripts/mcp-tokens.ts): rows of app_tokens with kind 'pat', an absolute expiry, and
-- one active name per account (a revoked name may be used again; its row stays). Same as src/server/db.ts.
ALTER TABLE app_tokens ADD COLUMN kind TEXT;
ALTER TABLE app_tokens ADD COLUMN expires_at INTEGER;
CREATE UNIQUE INDEX IF NOT EXISTS app_tokens_pat_name ON app_tokens(user_id, label) WHERE kind = 'pat' AND revoked_at IS NULL;
