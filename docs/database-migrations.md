# 数据库迁移（Atlas Versioned）

Furtalk 的数据库 schema 由 **Atlas Versioned SQL migration** 管理。应用二进制不执行任何
schema 变更，不包含 GORM `AutoMigrate`、Atlas 调用或嵌入式 SQL migration。
官方 Docker 镜像的 `/app/docker-entrypoint.sh` 会在启动应用进程前，使用镜像内置的 Atlas
Community v1.3.0 对目标数据库执行一次已提交的 versioned `migrate apply`。直接运行二进制、
使用自定义镜像或接管既有数据库时，迁移由部署流程显式执行。

- 期望 schema 定义来自 `internal/repository/model.All()`。
- 开发工具链使用 `tools/atlas-loader`（独立 Go module），从 `model.All()` 生成方言 DDL。
- 期望 schema SQL（`atlas/schema.sqlite.sql` / `atlas/schema.postgres.sql`）是**临时
  生成物**：loader 会在每次 diff / validate / inspect 前现场重建，文件已 gitignored，不进入 Git 历史。
- Atlas CLI 固定使用 **Atlas Community v1.3.0**。官方镜像从固定的
  `arigaio/atlas:1.3.0-alpine` 阶段复制 `/atlas`；非容器本地工具加入 `PATH`，或通过
  `ATLAS_BIN` 环境变量指定。
- 方言目录为 `migrations/sqlite` 与 `migrations/postgres`，各自持有独立的 SQL 历史与
  `atlas.sum` 校验文件，两种方言的版本号互不相同、互不相关。

## 开发环境

### Atlas CLI

- 安装 Atlas Community **v1.3.0** 预构建可执行文件并加入 `PATH`，或设置 `ATLAS_BIN`
  指向该文件。Atlas 不通过 `go install` 安装，官方已不再支持该方式。
- 运行 Atlas 命令前，确认 `atlas version` 输出包含 `v1.3.0`；`scripts/atlas.ps1` 的
  `preflight` 会自动强制该契约。

### SQLite dev database

SQLite 环境使用内存 dev database，无需任何外部服务。

### PostgreSQL dev database

PostgreSQL 的 diff / validate / inspect 使用**专用、可写、允许 Atlas 重建与清理**的
dev database。该数据库不能是业务目标库或远程生产库。连接信息通过环境变量注入，且该变量
**不得写入仓库、日志、文档示例或任务记录**：

```text
$env:ATLAS_POSTGRES_DEV_URL = "postgres://<user>:<pass>@<host>:<port>/<dedicated-dev-db>?search_path=public&sslmode=require"
task atlas:diff-postgres -- <名字>
```

未设置该变量时，PostgreSQL 命令会在启动前失败。

## 生成迁移（标准开发流程）

GORM 模型发生变更时，按以下顺序生成、审核并提交 migration：

1. 修改模型 tag / 关系，确保 `model.All()` 覆盖全部持久化模型且依赖顺序正确。
2. 为每种方言生成带名字的 migration：

   ```text
   task atlas:diff-sqlite -- <名字>
   task atlas:diff-postgres -- <名字>
   ```

   两条命令都会先重新生成期望 schema SQL（`atlas/schema.sqlite.sql` /
   `atlas/schema.postgres.sql`），再让 Atlas 对比 migration 目录回放状态与期望状态，
   产出新 SQL 与更新的 `atlas.sum`。运行 PostgreSQL 命令前必须设置
   `ATLAS_POSTGRES_DEV_URL`。
3. **人工审核**两份新生成的 SQL：逐条确认语义、破坏性语句、数据丢失风险、锁、默认值、
   约束、索引与方言特有重建行为。审核并修改尚未应用的新 SQL 后，执行对应目录的
   `task atlas:hash-sqlite`（或 `atlas:hash-postgres`）刷新 `atlas.sum`。
4. 校验目录完整性与可回放性：

   ```text
   task atlas:validate-sqlite
   task atlas:validate-postgres
   ```

5. 再次运行 diff 应报告「目录与期望状态同步，无变更」；若有变更，说明期望 schema 与
   migration 未同步，回到步骤 2。
6. 将模型修改、审核后的 migration SQL 与更新的 `atlas.sum` 一并提交。
   `atlas/schema.*.sql` 是临时生成物，不需要提交。

> 已应用的 migration 文件不可修改。修正必须新增 roll-forward migration。
> 生成命令不会执行 `migrate apply`、`schema apply` 或 Git 操作。

## 标准容器启动（部署）

官方镜像从 `FURTALK_DATABASE_*` 环境变量读取数据库连接字段，因为入口脚本在
Viper 读取应用配置之前就需要将目标传给 Atlas：

- SQLite：`FURTALK_DATABASE_DIALECT=sqlite` 与 `FURTALK_DATABASE_PATH`。
- PostgreSQL：`FURTALK_DATABASE_DIALECT=postgres` 与 `FURTALK_DATABASE_HOST`、
  `FURTALK_DATABASE_PORT`、`FURTALK_DATABASE_NAME`、`FURTALK_DATABASE_USER`、
  `FURTALK_DATABASE_PASSWORD`、`FURTALK_DATABASE_SSL_MODE`。

根目录 `docker-compose.yml` 是 SQLite 默认部署示例：它使用 GHCR 官方镜像、把数据库文件
持久化到命名卷的 `/app/data/furtalk.db`，并保留镜像 entrypoint 的 pre-start `migrate apply`
与默认 `--web`。Compose 通过环境插值接收其余必需静态配置；替换后的
`configs/.env.example` 可保存为未跟踪的 `.env`。使用 PostgreSQL 时，部署配置必须提供六个
PostgreSQL 连接字段，且不可将 Compose 的 SQLite 默认值用于 PostgreSQL。

## 非容器应用迁移（部署）

直接运行二进制或自定义镜像时，运维人员在应用进程外显式提供目标 URL 并执行部署流程：

1. 选择目标方言目录与目标数据库 URL。目标 URL 通过命令参数传入，**不得写入仓库**，也
   不得复用 `ATLAS_POSTGRES_DEV_URL`。
2. **备份目标数据库**：SQLite 在安全停写状态下复制数据库文件；PostgreSQL 按部署策略
   执行备份 / PITR。
3. 检查状态：

   ```text
   atlas migrate status --dir "file://migrations/sqlite" --url "<目标 SQLite URL>"
   atlas migrate status --dir "file://migrations/postgres" --url "<目标 PostgreSQL URL>"
   ```

4. 预览待执行 SQL：

   ```text
   atlas migrate apply --dir "file://migrations/sqlite" --url "<目标 URL>" --dry-run
   atlas migrate apply --dir "file://migrations/postgres" --url "<目标 URL>" --dry-run
   ```

5. 执行 apply：

   ```text
   atlas migrate apply --dir "file://migrations/sqlite" --url "<目标 URL>"
   atlas migrate apply --dir "file://migrations/postgres" --url "<目标 URL>"
   ```

6. 确认 `status` 全部为最新，再启动 / 重启应用。

> apply 期间发生错误时，停止执行并排查原因；按部署策略恢复备份或修正问题后再继续。
> CI 的 schema 生成/校验流程不会执行目标库 apply；只有标准容器入口在启动应用前执行已提交
> migration apply。任何其他自动化路径都不得调用目标库 schema mutation。

## 初始接管（一次性）

双方言已提交完整的 initial migration：

- **新空库**：直接执行应用迁移的步骤 4–6，initial SQL 会创建全部表。
- **已有库**（由旧版本 GORM `AutoMigrate` 创建且 schema 一致）：首次 apply 通过
  `--baseline <version>` 登记起始版本，避免重复执行建表 SQL：

   ```text
   atlas migrate apply --dir "file://migrations/sqlite" --url "<目标 URL>" --baseline 20260816021550
   atlas migrate apply --dir "file://migrations/postgres" --url "<目标 URL>" --baseline 20260816024330
   ```

   - 使用 `--baseline` 前必须**只读确认**现有 schema 与对应方言期望状态一致；发现
     drift 时停止，不得使用 baseline 隐藏差异。
   - 两个目录的 initial version 不同：SQLite 为 `20260816021550_initial`，
     PostgreSQL 为 `20260816024330_initial`。若后续目录新增了 migration，以
     `atlas migrate status` 输出的实际版本号为准。

> 远程 schema 一致性检查是一次性接管步骤。接管完成后的常规版本迭代，`migrate diff`
> 只使用已提交 migration 目录、当前 GORM models 与对应 dev database，不连接业务数据库。
> 显式连接目标业务库执行 status / dry-run / apply 属于 migration 部署，不是
> diff 生成输入。

## 版本契约与回滚边界

- 版本固定：`.atlas-version` = `v1.3.0`；`scripts/atlas.ps1` 对所有 Atlas 命令做 preflight。
- Atlas / provider 升级通过独立的显式审核变更完成，升级后重新生成并对比两种方言的期望 schema
  与 baseline fixtures。
- 破坏性变更遵循 **expand / migrate / contract**；不生成 down-migration 作为常规回滚手段。
- 已应用的 migration 保持不可变：不可回退与编辑历史文件。需要修正时新增 roll-forward
  migration，或按部署策略从备份恢复，并在 schema 兼容时才回滚应用版本。

## 迁移规则速查

- 生成 → 人工审核 SQL → 校验 → 刷新 checksum → 提交 → 非容器外部手动 apply，或由标准
  容器入口在启动应用前 apply。
- 应用二进制、生成命令与 CI/CD 均不会自动 apply；容器入口是唯一新增的 pre-start apply 边界。
- 已应用 migration 不可变；未应用的新 SQL 审核修改后必须刷新 `atlas.sum` 并重新验证。
- 任何命令不得泄露 `ATLAS_POSTGRES_DEV_URL` 或目标业务库凭据。
