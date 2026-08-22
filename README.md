# Furtalk

Furtalk 是一个自托管的网站评论系统。后端提供完整的评论 API 与管理能力，拥有独立的管理控制台，支持匿名评论、认证评论与人工审核等多种部署形态。

- **轻量可自托管**：单二进制进程，支持 SQLite 与 PostgreSQL，可选 Redis 缓存。
- **可嵌入**：评论组件为独立 ES module，Shadow DOM 隔离样式，按页面键挂载即可使用。
- **多身份体系**：密码、邮箱验证码、Passkey（WebAuthn）与主流 OAuth/OIDC 提供商。
- **可运营**：站点/线程/用户管理、评论审核与垃圾标记、邮件通知、CAPTCHA 保护。

## 特性

- 匿名与认证两种评论模式，可全局或按页面开关评论。
- 审核策略：直接发布或人工审核；垃圾标记与恢复。
- 认证方式：
  - 邮箱 + 密码、邮箱一次性验证码；
  - Passkey（WebAuthn）；
  - OAuth/OIDC：GitHub、Google、GitLab、Microsoft、Twitter、Gitea、Apple、Discord、LINE、Mastodon 及自定义 OIDC。
- CAPTCHA 支持 Turnstile、reCAPTCHA、hCaptcha 与 CAP，可按动作（登录、评论等）独立配置。
- 邮件通知：回复、审核发布、密码重置与登录验证码，模板化渲染。
- 多站点管理：支持接入多个站点。
- 隐私控制：IP / User-Agent 捕获粒度可配置。
- 邮箱域名白名单 / 黑名单，Gravatar 头像，远程表情目录（emoji-pack 协议）。
- 统一的 JSON 错误信封、限流、可信代理、优雅关闭与安全响应头。

## 技术栈

| 层     | 技术                                                                      |
| ------ | ------------------------------------------------------------------------- |
| 后端   | Go ≥ 1.25.13、Gin、GORM、go.uber.org/fx、Viper                            |
| 数据库 | SQLite（纯 Go glebarez 驱动）或 PostgreSQL（pgx）                         |
| 缓存   | 进程内缓存（默认）或 Redis                                                |
| 认证   | golang-jwt（HS256）、WebAuthn、go-oidc                                    |
| 邮件   | go-mail（SMTP）                                                           |
| 迁移   | Atlas Community v1.3.0 Versioned SQL                                      |
| 前端   | Web 控制台：React 19 + Vite + TanStack Router；评论组件：Lit + Shadow DOM |

## 仓库结构

```text
cmd/app            服务入口（fx 装配）
internal/app       组合根：生命周期、就绪检查、依赖装配
internal/domain    领域类型与错误 sentinel
internal/handler   HTTP 处理器与请求/响应 DTO
internal/router    路由与全局中间件（安全头、限流、鉴权等）
internal/service   业务用例（bootstrap / comment / identity / notification / setting / site）
internal/repository 数据持久化
internal/platform  跨领域基础设施（config / database / cache / token / oauth / captcha / mailer ...）
configs            配置模板与邮件模板
migrations         数据库迁移（sqlite / postgres）
docs               API 契约、迁移说明与 Swagger 生成物
web/               管理控制台 SPA（子模块，见 web/README.md）
widget/            可嵌入评论组件（子模块，见 widget/README.md）
```

## 快速开始

### 环境要求

- Go ≥ 1.25.13
- pnpm（构建 Web 与 Widget）
- Task（推荐，`task` 命令；详见 Taskfile.yml）
- Atlas Community v1.3.0（非容器部署手动迁移需要；官方镜像已内置，见 `docs/database-migrations.md`）

### 构建

```bash
task build        # 后端 + Web + Widget 全量构建
go build ./...    # 仅构建后端（不包含 Web 资源）
go run ./cmd/app  # 以开发默认值启动，不开启内嵌 Web
```

普通后端构建不会读取 Web 子模块或 Node 依赖。需要生成带控制台的二进制时，先构建并暂存 Web 产物，再显式使用 `embed` build tag：

```bash
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
./scripts/stage-web.sh
CGO_ENABLED=0 go build -tags embed -o furtalk ./cmd/app
./furtalk --web
```

### 首次运行

1. 准备静态配置。全部必需项来自配置文件或 `FURTALK_` 前缀环境变量，模板见 `configs/config.example.yaml`；配置优先级：非空环境变量 > 配置文件 > 内置默认值。
   必需项：
   - `FURTALK_HTTP_PUBLIC_BASE_URL` — 实例公开 Origin（OAuth、退订链接等）
   - `FURTALK_DATABASE_DIALECT` — `sqlite` 或 `postgres`
   - SQLite：`FURTALK_DATABASE_PATH`
   - PostgreSQL：`FURTALK_DATABASE_HOST` / `FURTALK_DATABASE_PORT` / `FURTALK_DATABASE_NAME` /
     `FURTALK_DATABASE_USER` / `FURTALK_DATABASE_PASSWORD` / `FURTALK_DATABASE_SSL_MODE`
   - `FURTALK_TOKENS_JWT_ISSUER` / `FURTALK_TOKENS_JWT_KEY`
   - `FURTALK_TOKENS_SECRET_KEY` — Provider 机密加密主密钥
   - `FURTALK_WEBAUTHN_RP_ID` / `FURTALK_WEBAUTHN_RP_ORIGINS`
2. 使用官方 Docker 镜像时，入口脚本会自动执行一次已提交的 versioned migration apply。直接运行二进制或使用自定义镜像时，仍需在应用进程外先完成 schema 迁移。应用二进制本身不会建表：

   ```bash
   atlas migrate apply --dir "file://migrations/sqlite" --url "<目标 SQLite URL>"
   # PostgreSQL：
   atlas migrate apply --dir "file://migrations/postgres" --url "<目标 PostgreSQL URL>"
   ```

3. 启动应用。全新实例的启动日志会打印一次性 setup token（10 分钟内有效）。
4. 访问 `/setup` 页面，填写 setup token、管理员邮箱、昵称与密码完成初始化，之后跳转
   `/login` 登录。

> 迁移细节（备份、dry-run、既有库 baseline 接管等）见 `docs/database-migrations.md`。

### Docker Compose（SQLite）

根目录 `docker-compose.yml` 提供一个使用 GHCR 官方镜像的 SQLite 单服务部署。数据保存在命名卷中的 `/app/data/furtalk.db`；宿主机的 `./configs` 会只读挂载到容器内 `/app/configs`，用于提供可选的 `config.yaml` 和邮件模板。先复制配置模板到未跟踪的 `.env` 并替换必需值，再启动：

```bash
cp configs/.env.example .env
# 编辑 .env，替换 JWT、Provider 加密和 WebAuthn 等占位值
docker compose up -d
```

如需使用 YAML 配置，可将 `configs/config.example.yaml` 复制为 `configs/config.yaml`。邮件模板位于 `configs/email`，应用只在启动时加载模板，修改后需重启容器。

默认使用稳定镜像 `latest`；可通过 `FURTALK_IMAGE_TAG=1.2.3` 固定已发布版本，也可用 `FURTALK_IMAGE` 指定完整镜像引用。

## 配置

启动时从配置文件和（或）环境变量一次性加载静态配置。完整 YAML 模板见 `configs/config.example.yaml`，以下为环境变量速查表。

| 环境变量                             | 级别           | 默认                   | 说明                                         |
| ------------------------------------ | -------------- | ---------------------- | -------------------------------------------- |
| `FURTALK_HTTP_ADDRESS`               | 建议           | `:8080`                | HTTP 监听地址                                |
| `FURTALK_HTTP_PUBLIC_BASE_URL`       | **必需**       | —                      | 实例公开 Origin（OAuth/退订链接等）          |
| `FURTALK_HTTP_TRUSTED_PROXIES`       | 建议           | 空                     | 可信代理 CIDR 列表                           |
| `FURTALK_HTTP_BODY_LIMIT`            | 建议           | `1048576`              | 请求体上限（字节）                           |
| `FURTALK_HTTP_RATE_LIMIT_RATE/BURST` | 建议           | `10`/`100`             | 令牌桶                                       |
| `FURTALK_HTTP_SHUTDOWN_TIMEOUT`      | 建议           | `10s`                  | 优雅关闭宽限                                 |
| `FURTALK_DATABASE_DIALECT`           | **必需**       | —                      | `sqlite` \| `postgres`                       |
| `FURTALK_DATABASE_PATH`              | 条件必需       | —                      | `sqlite` 时的数据库文件路径                  |
| `FURTALK_DATABASE_HOST`              | 条件必需       | —                      | `postgres` 主机；`sqlite` 时忽略             |
| `FURTALK_DATABASE_PORT`              | 条件必需       | —                      | `postgres` 端口（1-65535）                   |
| `FURTALK_DATABASE_NAME`              | 条件必需       | —                      | `postgres` 数据库名                          |
| `FURTALK_DATABASE_USER`              | 条件必需       | —                      | `postgres` 用户名                            |
| `FURTALK_DATABASE_PASSWORD`          | 条件必需       | —                      | `postgres` 密码                              |
| `FURTALK_DATABASE_SSL_MODE`          | 条件必需       | —                      | `postgres` SSL mode                          |
| `FURTALK_CACHE_REDIS_URL`            | 可选           | 空                     | 空 = 进程内缓存                              |
| `FURTALK_TOKENS_JWT_ISSUER`          | **必需**       | —                      | JWT issuer                                   |
| `FURTALK_TOKENS_JWT_ALGORITHM`       | 建议           | `HS256`                | 固定 HS256                                   |
| `FURTALK_TOKENS_JWT_KEY`             | **必需**       | —                      | 原始文本密钥，≥ 32 字节                      |
| `FURTALK_TOKENS_JWT_LIFETIME`        | 建议           | `168h`                 | 第一方 JWT 有效期                            |
| `FURTALK_TOKENS_WIDGET_JWT_LIFETIME` | 建议           | `24h`                  | 评论组件 JWT 有效期                          |
| `FURTALK_TOKENS_SECRET_KEY`          | **必需**       | —                      | Provider 机密加密主密钥，原始文本，≥ 32 字节 |
| `FURTALK_WEBAUTHN_RP_ID`             | **必需**       | —                      | WebAuthn RP 标识                             |
| `FURTALK_WEBAUTHN_RP_ORIGINS`        | **必需**       | —                      | WebAuthn 允许 Origin 列表                    |
| `FURTALK_WEBAUTHN_RP_NAME`           | 建议           | `Furtalk`              | WebAuthn RP 展示名                           |
| `FURTALK_OAUTH_CLIENT_TIMEOUT`       | 建议           | `10s`                  | OAuth HTTP 超时                              |
| `FURTALK_SMTP_HOST`                  | 可选           | 空                     | 空 = 通知惰性；设置后启用 SMTP               |
| `FURTALK_SMTP_PORT/TLS/TIMEOUT`      | 建议（启用时） | `587`/`starttls`/`30s` | SMTP 投递参数                                |
| `FURTALK_SMTP_FROM`                  | 必需（启用时） | —                      | SMTP 发件地址                                |
| `FURTALK_SMTP_USERNAME/PASSWORD`     | 可选           | 空                     | SMTP 凭据                                    |
| `FURTALK_LOGGING_FORMAT`             | 默认           | `text`                 | 后端日志输出格式：`json` 或 `text`           |

### 第三方登录回调部署

第三方 OAuth/OIDC 登录的回调入口是前端专用回调页 `https://<public-origin>/oauth/callback/{provider}`

后端与前端需要同源部署，共用同一 `FURTALK_HTTP_PUBLIC_BASE_URL`。

## 评论组件（Widget）

评论组件是独立的浏览器 ES module，通过 Shadow DOM 隔离样式，可嵌入任意静态站点：

```html
<script type="module" src="https://cdn.example.com/widget/furtalk.min.js"></script>
<furtalk-comments site-id="123" page-key="article-2026-08"></furtalk-comments>
```

- 构建：`pnpm --dir widget build`（`task widget:build`），产物包含
  未压缩的 `widget/dist/furtalk.js` 和 npm/CDN 使用的压缩版
  `widget/dist/furtalk.min.js`，两者均带 source map。
- 部署：将 `widget/dist/` 产物托管到独立 CDN / 静态托管，通过 `<script>` 加载；
  组件自动从 `import.meta.url` 推导 Furtalk 服务源（可用 `service-origin` 属性覆盖）。
- 部署要求：授权流程依赖 `window.opener`，禁止使用 `noopener`，也禁止对该流程设置
  `Cross-Origin-Opener-Policy: same-origin`（`same-origin-allow-popups` 兼容）；
  评论会话依赖 CHIPS Partitioned cookie。
- 挂载属性与详细约定见 `widget/README.md`。

## 管理控制台（Web）

Web 控制台是覆盖登录、OAuth 授权、站点/线程/用户/评论管理与设置的后台 SPA，独立构建与
部署，见 `web/README.md`。

## 质量验证

后端质量门由 Taskfile 封装（gofmt、vet、build、test、架构规则、CGO-free）：

```text
task build               # 后端 + Web + Widget 全量构建
task check               # 后端 + Web + Widget 全量质量门
task backend:check       # 后端质量门
task web:check           # Web 质量门
task widget:check        # Widget 质量门
task release             # 生成 bin/ 下四个发布二进制（linux/windows × amd64/arm64）
task test-race           # 后端竞态检测测试
task docker:check        # 校验 Atlas 容器入口、方言选择与镜像文件契约
```

## 文档

- `docs/contract.md` — HTTP 端点、认证、数据库与事件契约。
- `docs/swagger/` — Swagger 生成物（drift 检查基线）。
- `docs/database-migrations.md` — 数据库迁移流程与回滚边界。
- `web/README.md` — 管理控制台。
- `widget/README.md` — 评论组件。
