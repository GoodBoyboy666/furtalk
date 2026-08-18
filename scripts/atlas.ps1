#!/usr/bin/env pwsh
# Atlas 开发命令入口：版本契约校验、期望 schema 生成、diff、validate、hash。
# 所有命令都以 .atlas-version 声明的 Atlas Community 版本为准，版本不符立即失败。
# 任何命令都不会执行 migrate apply、schema apply、Git 操作或连接业务目标库。
param(
	[Parameter(Mandatory = $true)][string]$Command,
	[string]$Name = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$atlasBin = if ($env:ATLAS_BIN) { $env:ATLAS_BIN } else { "atlas" }
$expected = (Get-Content (Join-Path $root ".atlas-version")).Trim()

function Invoke-Preflight {
	$version = & $atlasBin version 2>&1 | Out-String
	if ($LASTEXITCODE -ne 0) {
		Write-Error "atlas CLI 不可用（$atlasBin）。请安装 Atlas Community 并加入 PATH，或设置 ATLAS_BIN 指向可执行文件。"
	}
	if ($version -notmatch [regex]::Escape($expected)) {
		Write-Error "Atlas 版本契约不满足：期望 $expected，实际输出：$version"
	}
	Write-Host "Atlas 版本契约满足：$expected"
}

function Invoke-Loader {
	param([string]$Dialect)
	$env:GOWORK = "off"
	$env:CGO_ENABLED = "0"
	try {
		$out = & go -C (Join-Path $root "tools/atlas-loader") run -mod=readonly . $Dialect 2>&1
		if ($LASTEXITCODE -ne 0) {
			Write-Error "loader 生成 $Dialect 期望 schema 失败：$out"
		}
		$target = Join-Path $root ("atlas/schema." + $Dialect + ".sql")
		$out | Out-File -FilePath $target -Encoding utf8
		Write-Host "已重新生成 $target"
	} finally {
		Remove-Item Env:GOWORK -ErrorAction SilentlyContinue
		Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
	}
}

function Assert-PostgresDevUrl {
	if (-not $env:ATLAS_POSTGRES_DEV_URL) {
		Write-Error "缺少 ATLAS_POSTGRES_DEV_URL：PostgreSQL 命令需要专用可写 dev database URL（不得使用业务目标库）。"
	}
}

# Invoke-Atlas 执行 atlas 并透传输出；失败时抛出包含 Atlas 原始错误的终止错误。
function Invoke-Atlas {
	param([string[]]$AtlasArgs)
	$output = & $atlasBin @AtlasArgs 2>&1
	if ($LASTEXITCODE -ne 0) {
		$detail = ($output | ForEach-Object { "$_" }) -join "`n"
		Write-Error "atlas $($AtlasArgs -join ' ') 失败：$detail"
	}
	$output
}

function Invoke-Diff {
	param([string]$EnvName, [string]$Dialect)
	if (-not $Name) {
		Write-Error "migrate diff 需要 migration 名称（例如：task atlas:diff-sqlite -- add_users_bio）。"
	}
	Invoke-Preflight
	Invoke-Loader -Dialect $Dialect
	if ($EnvName -eq "postgres") {
		Assert-PostgresDevUrl
	}
	Invoke-Atlas -AtlasArgs @("migrate", "diff", $Name, "--env", $EnvName)
}

function Invoke-Validate {
	param([string]$EnvName, [string]$Dialect)
	Invoke-Preflight
	# validate 会重放 migration 目录并与期望 schema 对比，需要现场生成 schema 文件。
	Invoke-Loader -Dialect $Dialect
	Invoke-Atlas -AtlasArgs @("migrate", "validate", "--env", $EnvName)
}

function Invoke-Hash {
	param([string]$EnvName)
	Invoke-Preflight
	Invoke-Atlas -AtlasArgs @("migrate", "hash", "--env", $EnvName)
}

function Invoke-Inspect {
	param([string]$EnvName, [string]$Dialect)
	Invoke-Preflight
	Invoke-Loader -Dialect $Dialect
	if ($EnvName -eq "postgres") {
		Assert-PostgresDevUrl
	}
	Invoke-Atlas -AtlasArgs @("schema", "inspect", "--env", $EnvName, "--url", "env://src")
}

switch ($Command) {
	"preflight" { Invoke-Preflight }
	"diff-sqlite" { Invoke-Diff -EnvName "sqlite" -Dialect "sqlite" }
	"diff-postgres" { Invoke-Diff -EnvName "postgres" -Dialect "postgres" }
	"validate-sqlite" { Invoke-Validate -EnvName "sqlite" -Dialect "sqlite" }
	"validate-postgres" { Invoke-Validate -EnvName "postgres" -Dialect "postgres" }
	"hash-sqlite" { Invoke-Hash -EnvName "sqlite" }
	"hash-postgres" { Invoke-Hash -EnvName "postgres" }
	"inspect-sqlite" { Invoke-Inspect -EnvName "sqlite" -Dialect "sqlite" }
	"inspect-postgres" { Invoke-Inspect -EnvName "postgres" -Dialect "postgres" }
	default {
		Write-Error "未知命令：$Command。可用命令：preflight / diff-sqlite / diff-postgres / validate-sqlite / validate-postgres / hash-sqlite / hash-postgres / inspect-sqlite / inspect-postgres"
	}
}
