#!/bin/sh

set -eu

fail() {
    printf '%s\n' "docker entrypoint: $1" >&2
    exit 1
}

require_nonblank() {
    value=$1
    message=$2
    case "$value" in
        *[![:space:]]*) ;;
        *) fail "$message" ;;
    esac
}

default_configs_dir=/app/default-configs
configs_dir=/app/configs

if [ ! -d "$default_configs_dir" ]; then
    fail "default config directory is missing"
fi
if ! mkdir -p "$configs_dir"; then
    fail "cannot create config directory"
fi

config_entry=$(find "$configs_dir" -mindepth 1 -maxdepth 1 -print -quit)
if [ -z "$config_entry" ]; then
    if ! cp -R "$default_configs_dir"/. "$configs_dir"/; then
        fail "cannot populate config directory"
    fi
fi

dialect=${FURTALK_DATABASE_DIALECT:-}
if [ -z "$dialect" ]; then
    fail "FURTALK_DATABASE_DIALECT is required"
fi

case "$dialect" in
    sqlite)
        require_nonblank "${FURTALK_DATABASE_PATH:-}" "FURTALK_DATABASE_PATH is required for sqlite"
        ;;
    postgres)
        require_nonblank "${FURTALK_DATABASE_HOST:-}" "FURTALK_DATABASE_HOST is required for postgres"
        [ -n "${FURTALK_DATABASE_PORT:-}" ] || fail "FURTALK_DATABASE_PORT is required for postgres"
        require_nonblank "${FURTALK_DATABASE_NAME:-}" "FURTALK_DATABASE_NAME is required for postgres"
        require_nonblank "${FURTALK_DATABASE_USER:-}" "FURTALK_DATABASE_USER is required for postgres"
        require_nonblank "${FURTALK_DATABASE_PASSWORD:-}" "FURTALK_DATABASE_PASSWORD is required for postgres"
        require_nonblank "${FURTALK_DATABASE_SSL_MODE:-}" "FURTALK_DATABASE_SSL_MODE is required for postgres"
        case "$FURTALK_DATABASE_PORT" in
            *[!0-9]*) fail "FURTALK_DATABASE_PORT must be between 1 and 65535" ;;
        esac

        # Strip leading zeroes before the numeric comparison.  Besides accepting
        # normal zero-padded ports, this bounds the value passed to the POSIX
        # shell's integer parser.  A string containing more digits than the
        # parser can represent must fail closed instead of allowing an
        # "Illegal number" diagnostic to bypass the `if` condition.
        port_value=$FURTALK_DATABASE_PORT
        while [ "${port_value#0}" != "$port_value" ]; do
            port_value=${port_value#0}
        done
        [ -n "$port_value" ] || fail "FURTALK_DATABASE_PORT must be between 1 and 65535"
        case "$port_value" in
            [0-9]|[0-9][0-9]|[0-9][0-9][0-9]|[0-9][0-9][0-9][0-9]|[0-9][0-9][0-9][0-9][0-9]) ;;
            *) fail "FURTALK_DATABASE_PORT must be between 1 and 65535" ;;
        esac
        if [ "$port_value" -lt 1 ] || [ "$port_value" -gt 65535 ]; then
            fail "FURTALK_DATABASE_PORT must be between 1 and 65535"
        fi
        case "$FURTALK_DATABASE_SSL_MODE" in
            disable|allow|prefer|require|verify-ca|verify-full) ;;
            *) fail "FURTALK_DATABASE_SSL_MODE is invalid" ;;
        esac
        ;;
    *)
        fail "unsupported database dialect"
        ;;
esac

/usr/local/bin/atlas migrate apply --config file:///app/atlas.runtime.hcl --env "runtime-$dialect"

exec /app/furtalk "$@"
