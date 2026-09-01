# migrate-provider-secrets

This tool converts Furtalk provider secret envelopes from v1 to v2.

- v1 decrypts with the legacy raw 32-byte key.
- v2 derives an AES-256-GCM key from `FURTALK_TOKENS_SECRET_KEY` with the
  application KDF contract.
- The default mode is a complete dry-run. Only `--execute` commits changes.
- SQLite and PostgreSQL use the same split database environment variables as
  the application and `migrate-artalk`.

Before running the tool:

1. Back up the database and verify that it can be restored.
2. Stop application writers for the whole conversion.
3. Run a dry-run and inspect its aggregate report.
4. Run the same command again with `--execute`.

## Environment

Provider keys are never accepted as command-line arguments:

```text
FURTALK_TOKENS_SECRET_KEY
FURTALK_TOKENS_LEGACY_SECRET_KEY
```

The new key must contain at least 32 bytes. The legacy key must contain
exactly 32 bytes. If the legacy variable is omitted, the new key is reused
only when it is exactly 32 bytes.

Both key values are consumed verbatim as raw UTF-8 bytes, matching the
application configuration contract. Leading and trailing whitespace is part of
the key and is never trimmed; keep variable expansions quoted when invoking the
tool. PostgreSQL passwords are likewise passed to the database connector
without trimming.

Database variables are:

```text
FURTALK_DATABASE_DIALECT=sqlite|postgres
FURTALK_DATABASE_PATH=/app/data/furtalk.db
FURTALK_DATABASE_HOST=...
FURTALK_DATABASE_PORT=5432
FURTALK_DATABASE_NAME=...
FURTALK_DATABASE_USER=...
FURTALK_DATABASE_PASSWORD=...
FURTALK_DATABASE_SSL_MODE=require
```

Only the fields for the selected dialect are used. Equivalent
`--target-*` flags are available for database connection fields.

## Examples

SQLite dry-run:

```sh
FURTALK_TOKENS_SECRET_KEY="$NEW_KEY" \
FURTALK_TOKENS_LEGACY_SECRET_KEY="$OLD_KEY" \
FURTALK_DATABASE_DIALECT=sqlite \
FURTALK_DATABASE_PATH=/app/data/furtalk.db \
/app/migrate-provider-secrets
```

After reviewing the report, repeat the command with `--execute`.

The tool converts CAPTCHA, OAuth/OIDC, spam, and notification provider rows
in one transaction. Rows without a secret are skipped safely; current v2 rows
are authenticated and counted. An unknown version, authentication failure,
or write failure rolls back the entire operation. Dry-run also exercises the
write path and then rolls it back. Reports contain only per-kind counts and
never print keys, nonces, ciphertexts, or decrypted provider secrets.
