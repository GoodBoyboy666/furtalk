#!/bin/sh

# 验证发布 tag 解析与 Web 暂存脚本的关键成功/失败路径。
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
temporary_dir=$(mktemp -d)
cleanup() {
	rm -rf "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

stable_output=$("$script_dir/release-tag.sh" v1.2.3)
case $stable_output in
	*"tag=v1.2.3"*"version=1.2.3"*"prerelease=false"*) ;;
	*)
		printf 'stable tag output is incorrect:\n%s\n' "$stable_output" >&2
		exit 1
		;;
esac

beta_output=$("$script_dir/release-tag.sh" v1.2.3-beta.4)
case $beta_output in
	*"tag=v1.2.3-beta.4"*"version=1.2.3-beta.4"*"prerelease=true"*) ;;
	*)
		printf 'beta tag output is incorrect:\n%s\n' "$beta_output" >&2
		exit 1
		;;
esac

if "$script_dir/release-tag.sh" v1.2 >/dev/null 2>&1; then
	printf 'invalid tag was accepted\n' >&2
	exit 1
fi
if "$script_dir/release-tag.sh" v1.2.3-rc.1 >/dev/null 2>&1; then
	printf 'release candidate tag was accepted\n' >&2
	exit 1
fi
if "$script_dir/release-tag.sh" "$(printf 'v1.2.3\nmalicious')" >/dev/null 2>&1; then
	printf 'multi-line tag was accepted\n' >&2
	exit 1
fi

source_dir=$temporary_dir/web-dist
stage_dir=$temporary_dir/staged
mkdir -p "$source_dir/assets"
printf '<html>test</html>\n' > "$source_dir/index.html"
printf 'asset\n' > "$source_dir/assets/app.js"
mkdir -p "$stage_dir"
printf 'stale\n' > "$stage_dir/stale.txt"
FURTALK_WEB_DIST=$source_dir FURTALK_WEB_STAGE=$stage_dir "$script_dir/stage-web.sh" >/dev/null
if [ ! -f "$stage_dir/index.html" ] || [ ! -f "$stage_dir/assets/app.js" ]; then
	printf 'staged bundle is incomplete\n' >&2
	exit 1
fi
if [ -e "$stage_dir/stale.txt" ]; then
	printf 'staged bundle retained stale content\n' >&2
	exit 1
fi

if FURTALK_WEB_DIST=$temporary_dir/missing FURTALK_WEB_STAGE=$temporary_dir/missing-stage \
	"$script_dir/stage-web.sh" >/dev/null 2>&1; then
	printf 'missing Web bundle was accepted\n' >&2
	exit 1
fi

printf 'release script checks passed\n'
