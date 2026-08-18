# Runtime-only Atlas configuration for the standard container image.
# The application configuration and the migration target deliberately share the
# same FURTALK_DATABASE_* environment variables, but this file is never used by
# development schema-generation commands.

locals {
  postgres_user     = replace(urlescape(getenv("FURTALK_DATABASE_USER")), "+", "%20")
  postgres_password = replace(urlescape(getenv("FURTALK_DATABASE_PASSWORD")), "+", "%20")
  postgres_host_raw = trimspace(getenv("FURTALK_DATABASE_HOST"))
  postgres_host     = startswith(local.postgres_host_raw, "[") && endswith(local.postgres_host_raw, "]") ? trimsuffix(trimprefix(local.postgres_host_raw, "["), "]") : local.postgres_host_raw
  postgres_hostport = length(regexall(":", local.postgres_host)) > 0 ? format("[%s]", local.postgres_host) : local.postgres_host
}

env "runtime-sqlite" {
  url = urlqueryset(
    urlsetpath("sqlite://", getenv("FURTALK_DATABASE_PATH")),
    "_fk",
    "1"
  )
  migration {
    dir = "file:///app/migrations/sqlite"
  }
}

env "runtime-postgres" {
  url = urlqueryset(
    urlqueryset(
      urlsetpath(
        "postgres://${local.postgres_user}:${local.postgres_password}@${local.postgres_hostport}:${getenv("FURTALK_DATABASE_PORT")}/database",
        "/${getenv("FURTALK_DATABASE_NAME")}"
      ),
      "search_path",
      "public"
    ),
    "sslmode",
    getenv("FURTALK_DATABASE_SSL_MODE")
  )
  migration {
    dir = "file:///app/migrations/postgres"
  }
}
