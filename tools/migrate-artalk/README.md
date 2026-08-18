# Artalk 评论迁移工具

本工具把 Artalk 官方导出的 Artrans 数据导入 Furtalk。工具自身及其测试全部位于
`tools/migrate-artalk/`，不属于 Furtalk 运行时。

支持 SQLite 和 PostgreSQL 目标库。源数据统一读取 Artrans，因此 Artalk 原来使用
SQLite、MySQL 或 PostgreSQL 都不影响迁移。

## 迁移前准备

1. 在 Artalk 控制中心导出 Artrans，或在 Artalk 服务器执行：

   ```bash
   artalk export ./artalk.artrans
   ```

2. 确保 Furtalk 已完成 Atlas 数据库迁移，并停止 Furtalk 服务，避免迁移期间并发写入。
3. 备份目标数据库。SQLite 需要备份数据库文件及可能存在的 `-wal`、`-shm` 文件；
   PostgreSQL 使用常规数据库备份工具。

## SQLite 用法

先执行默认的 dry-run。它会执行完整解析和数据库约束检查，但最终回滚所有写入：

```bash
FURTALK_DATABASE_DIALECT=sqlite \
FURTALK_DATABASE_PATH=/app/data/furtalk.db \
go run ./tools/migrate-artalk --input ./artalk.artrans
```

确认报告无误后正式提交：

```bash
FURTALK_DATABASE_DIALECT=sqlite \
FURTALK_DATABASE_PATH=/app/data/furtalk.db \
go run ./tools/migrate-artalk --input ./artalk.artrans --execute
```

也可以用 `--target-dialect sqlite --target-path /path/to/furtalk.db` 代替环境变量。

## PostgreSQL 用法

目标连接字段与 Furtalk 使用相同的环境变量：

```bash
FURTALK_DATABASE_DIALECT=postgres \
FURTALK_DATABASE_HOST=127.0.0.1 \
FURTALK_DATABASE_PORT=5432 \
FURTALK_DATABASE_NAME=furtalk \
FURTALK_DATABASE_USER=furtalk \
FURTALK_DATABASE_PASSWORD='replace-me' \
FURTALK_DATABASE_SSL_MODE=require \
go run ./tools/migrate-artalk --input ./artalk.artrans
```

正式迁移同样需要追加 `--execute`。密码建议只通过环境变量传入，避免出现在命令行
历史和进程列表中。

## 站点映射

默认情况下，工具从每条 Artran 的 `site_name` 和 `site_urls` 解析站点：

- 按规范化后的 canonical URL 复用目标站点；不存在时创建站点。
- `site_urls` 中的合法 Origin 会加入 Furtalk 站点白名单。
- 非本机的明文 HTTP Origin 不会导入，因为 Furtalk 只接受安全的远程 Origin。
- 源数据没有可用 URL 时，可传 `--default-site-url https://blog.example.com`。

如果目标站点已经在 Furtalk 中创建，推荐显式指定 ID：

```bash
go run ./tools/migrate-artalk \
  --input ./artalk.artrans \
  --target-dialect sqlite \
  --target-path /app/data/furtalk.db \
  --target-site-id 1
```

`--target-site-id` 会把源文件中的全部 Artalk 站点合并进该 Furtalk 站点。为避免重复，
工具会拒绝向已经含有评论的目标站点导入；若需要重新执行，请先恢复迁移前备份。

## 字段映射

| Artalk | Furtalk | 说明 |
| --- | --- | --- |
| `id` / `rid` | `parent_id` / `root_id` / `depth` | 自动拓扑排序并重建完整回复树，源 ID 不直接复用 |
| `content` | `body_markdown` | 原样保留 Markdown |
| `is_pending` | `status` | `true` 为 `pending`，否则为 `published` |
| `created_at` / `updated_at` | 同名时间字段 | 保留时间并统一存为 UTC |
| `nick` / `email` / `link` | 用户资料 | 按规范化邮箱合并用户；目标已有用户保持原资料和角色 |
| `ip` / `ua` | 评论隐私字段 | 默认 `full`；可分别用 `--ip-mode`、`--ua-mode` 设为 `coarse` 或 `none` |
| `page_key` / `page_title` | thread | 页面键不变，采用最新的非空标题 |

Artrans 不包含可安全迁移到 Furtalk 的登录凭据，因此新用户不会获得密码，邮箱也不会被
自动标记为已验证。无效或空邮箱会替换为确定性的 `@artalk.invalid` 占位地址。

Furtalk 当前没有投票、置顶、折叠、徽章和“页面仅管理员评论”的等价字段，这些值不会
写入数据库，但迁移报告会分别统计，便于人工核对。徽章不会转换为管理员角色，以避免
从展示字段提升权限。

## 其他选项

```bash
go run ./tools/migrate-artalk --help
```

- `--source-timezone Asia/Shanghai`：仅用于没有 UTC offset 的旧版时间；官方新版导出时间
  自带 offset，不受此选项影响。
- `--ip-mode none|coarse|full`：IP 的目标隐私级别，默认 `full`。
- `--ua-mode none|coarse|full`：User-Agent 的目标隐私级别，默认 `full`。
- `--input -`：从标准输入读取；输入也可以是 gzip 压缩的 Artrans。

工具在一个数据库事务中迁移全部站点、用户、页面和评论。任意记录失败都会回滚整次迁移。
