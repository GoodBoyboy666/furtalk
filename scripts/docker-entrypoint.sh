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
data_dir=/app/data

if [ ! -d "$default_configs_dir" ]; then
    fail "default config directory is missing"
fi

if ! mkdir -p "$configs_dir"; then
    fail "cannot create config directory"
fi

#
# 初始化配置
#
# entrypoint 此时以 root 运行。
#
config_uid=$(stat -c '%u' "$configs_dir")
config_gid=$(stat -c '%g' "$configs_dir")

config_entry=$(find "$configs_dir" -mindepth 1 -maxdepth 1 -print -quit)

if [ -z "$config_entry" ]; then
    printf '%s\n' "docker entrypoint: populating default configs"

    if ! cp -R "$default_configs_dir"/. "$configs_dir"/; then
        fail "cannot populate config directory"
    fi

    # 改回宿主机 configs 目录的 owner。
    chown -R "$config_uid:$config_gid" "$configs_dir"
fi

#
# data 是程序运行时数据，应由 furtalk 用户拥有。
#
if ! mkdir -p "$data_dir"; then
    fail "cannot create data directory"
fi

chown furtalk:furtalk "$data_dir"

#
# 数据库配置检查
#

dialect=${FURTALK_DATABASE_DIALECT:-}

if [ -z "$dialect" ]; then
    fail "FURTALK_DATABASE_DIALECT is required"
fi

case "$dialect" in
    sqlite)
        require_nonblank \
            "${FURTALK_DATABASE_PATH:-}" \
            "FURTALK_DATABASE_PATH is required for sqlite"
        ;;

    postgres)
        require_nonblank \
            "${FURTALK_DATABASE_HOST:-}" \
            "FURTALK_DATABASE_HOST is required for postgres"

        [ -n "${FURTALK_DATABASE_PORT:-}" ] \
            || fail "FURTALK_DATABASE_PORT is required for postgres"

        require_nonblank \
            "${FURTALK_DATABASE_NAME:-}" \
            "FURTALK_DATABASE_NAME is required for postgres"

        require_nonblank \
            "${FURTALK_DATABASE_USER:-}" \
            "FURTALK_DATABASE_USER is required for postgres"

        require_nonblank \
            "${FURTALK_DATABASE_PASSWORD:-}" \
            "FURTALK_DATABASE_PASSWORD is required for postgres"

        require_nonblank \
            "${FURTALK_DATABASE_SSL_MODE:-}" \
            "FURTALK_DATABASE_SSL_MODE is required for postgres"

        case "$FURTALK_DATABASE_PORT" in
            *[!0-9]*)
                fail "FURTALK_DATABASE_PORT must be between 1 and 65535"
                ;;
        esac

        port_value=$FURTALK_DATABASE_PORT

        while [ "${port_value#0}" != "$port_value" ]; do
            port_value=${port_value#0}
        done

        [ -n "$port_value" ] \
            || fail "FURTALK_DATABASE_PORT must be between 1 and 65535"

        case "$port_value" in
            [0-9]|\
            [0-9][0-9]|\
            [0-9][0-9][0-9]|\
            [0-9][0-9][0-9][0-9]|\
            [0-9][0-9][0-9][0-9][0-9])
                ;;
            *)
                fail "FURTALK_DATABASE_PORT must be between 1 and 65535"
                ;;
        esac

        if [ "$port_value" -lt 1 ] || [ "$port_value" -gt 65535 ]; then
            fail "FURTALK_DATABASE_PORT must be between 1 and 65535"
        fi

        case "$FURTALK_DATABASE_SSL_MODE" in
            disable|allow|prefer|require|verify-ca|verify-full)
                ;;
            *)
                fail "FURTALK_DATABASE_SSL_MODE is invalid"
                ;;
        esac
        ;;

    *)
        fail "unsupported database dialect"
        ;;
esac

#
# 这里开始不再使用 root。
#
# Atlas 也必须以 furtalk 运行，否则 sqlite 数据库有可能被 root 创建。
#
su-exec furtalk:furtalk \
    /usr/local/bin/atlas migrate apply \
    --config file:///app/atlas.runtime.hcl \
    --env "runtime-$dialect"

#
# 最终应用同样以 furtalk 运行。
#
exec su-exec furtalk:furtalk /app/furtalk "$@"