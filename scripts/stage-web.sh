#!/bin/sh

# 将一次 Web 构建安全地复制到 Go embed 的忽略目录。
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
web_dist=${FURTALK_WEB_DIST:-$root_dir/web/dist}
stage_dir=${FURTALK_WEB_STAGE:-$root_dir/internal/platform/webui/dist}

if [ ! -d "$web_dist" ] || [ ! -f "$web_dist/index.html" ]; then
	printf 'Web bundle is missing: expected %s/index.html\n' "$web_dist" >&2
	exit 1
fi

stage_parent=$(dirname "$stage_dir")
mkdir -p "$stage_parent"

temporary_dir=${stage_dir}.tmp.$$
cleanup() {
	rm -rf "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

rm -rf "$temporary_dir"
mkdir "$temporary_dir"
cp -R "$web_dist"/. "$temporary_dir"/
rm -rf "$stage_dir"
mv "$temporary_dir" "$stage_dir"

trap - EXIT HUP INT TERM
printf 'staged Web bundle at %s\n' "$stage_dir"
