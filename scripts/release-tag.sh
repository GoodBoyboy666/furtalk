#!/bin/sh

# 严格解析 GitHub 发布 tag，并输出供 GitHub Actions 读取的键值行。
set -eu
LC_ALL=C
export LC_ALL

if [ "$#" -ne 1 ]; then
	printf 'usage: %s TAG\n' "$0" >&2
	exit 2
fi

tag=$1
case "$tag" in
	*[!0-9A-Za-z.-]*)
		printf 'invalid release tag: %s\n' "$tag" >&2
		exit 1
		;;
esac
if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-beta\.[0-9]+)?$'; then
	printf 'invalid release tag: %s\n' "$tag" >&2
	exit 1
fi

version=${tag#v}
prerelease=false
case "$tag" in
	*-beta.*) prerelease=true ;;
esac

printf 'tag=%s\n' "$tag"
printf 'version=%s\n' "$version"
printf 'prerelease=%s\n' "$prerelease"
