# Furtalk 约定清单

> 创建：2026-08-03
> 本文档面向 Furtalk 的接入方与维护开发者，定义对外承诺的稳定约定：HTTP 端点、
> JWT/Cookie/Origin 语义、DB 结构与约束。约定依据见 `docs/swagger/swagger.json`
> 与 `internal/router/router.go`、`internal/platform/httpx/cors.go`。

## 1. HTTP 端点（路径/方法）

### 健康探针（无 /api/v1 前缀，无需鉴权）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /health/live | 存活探针，200 ok |
| GET | /health/ready | 就绪探针，未就绪 503 not_ready |

### 公开端点

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | /api/v1/bootstrap/status | 公开 | 返回 `{required: bool}` |
| POST | /api/v1/bootstrap/admin | setup token | 410 bootstrap_unavailable / 409 / 400 / 422 |
| POST | /api/v1/notification-unsubscriptions | 公开 | 退订通知 |
| GET | /api/v1/widget/sites/{site_id}/runtime-config | 公开 | 站点运行时配置（含 CAPTCHA site key） |
| GET | /api/v1/captcha/config | 公开 | 按 action 查询的公共 CAPTCHA 配置，`Cache-Control: no-store` |
| GET | /api/v1/config | 公开 | 站点协议链接、同意版本与 Web 品牌主色白名单，`Cache-Control: no-store` |

### 公共 CAPTCHA 配置（/api/v1/captcha/config）

- 查询参数 `action` 必填（如 `password_login`、`comment`）；空/超长返回 422。
- 策略关闭或 action 不存在时返回 `{"required": false}`，无需读取 provider 配置。
- 策略开启时返回 `{"required": true, "captcha": {provider, site_key, api_endpoint?}}`；
  `api_endpoint` 仅 CAP 返回，解析为官方 widget 端点 `<endpoint>/<site_key>/`。
- 响应不含 `secret_key`；策略开启但 provider 缺失/损坏时返回 503。
- 该端点仅提供渲染提示；CAPTCHA 是否必填以业务写端点自身的校验为最终依据。

### 公共站点配置与登录协议（/api/v1/config）

- 响应只包含 `user_agreement_url`、`privacy_policy_url`、
  `legal_consent_version` 与 `brand_primary_color`；不会返回管理员设置列表、provider
  配置、密钥或内部设置。未配置的协议链接为空字符串，品牌主色默认 `#18181B`。
- 协议链接必须是空值或绝对 HTTPS 地址；品牌主色必须是标准 `#RRGGBB`。服务端返回
  `Cache-Control: no-store`，前端同样校验该白名单响应。
- 当任一协议链接存在时，登录页只显示已配置的协议入口，并要求用户勾选同意；未勾选
  时邮箱验证码发送、密码、Passkey 与 OAuth/OIDC 登录入口均不可执行。验证码登录页
  与重新发送也复用同一门禁。两个链接均为空时不显示门禁且保持原有登录行为。
- 浏览器只在 `localStorage` 保存命名空间化的已同意版本；存储缺失、损坏或不可用时
  默认未同意。协议版本只在管理员显式执行重新同意操作时递增，编辑链接或品牌颜色
  不会隐式失效已有浏览器同意状态。
- Web 根据单一品牌主色派生浅色/深色 `primary`、前景、焦点环、侧栏主色与主图表色；
  Widget 不读取这些字段，继续使用自身 Shadow DOM 样式与契约。

### Widget 运行时配置 CAPTCHA 投影（/api/v1/widget/sites/{site_id}/runtime-config）

- `captcha` 对象暴露 `comment` action 的公共渲染投影（不含 `anonymous_session`）：
  ```json
  {
    "captcha": {
      "comment": { "required": false }
    }
  }
  ```
- 该投影仅用于渲染：`required=true` 表示评论创建端点要求 CAPTCHA；
  `provider`/`site_key`/`api_endpoint` 仅当 provider 已配置时返回（`api_endpoint`
  仅 CAP，为 `<endpoint>/<site_key>/`）；策略开启但 provider 缺失时仍返回
  `required=true` 且不含 provider 细节，写端点按实时策略判定并失败关闭（503）。
- 响应不含 `secret_key`；写端点以实时策略为准，不以该投影作为判定依据。

### Widget 运行时配置远程表情目录（/api/v1/widget/sites/{site_id}/runtime-config）

- 实例级动态设置 `emoji_catalog_url`（公开 string，默认 `""`）。非空值必须是绝对
  HTTPS URL：允许 query（用于版本化/签名目录），不允许 userinfo 与 fragment，
  长度不超过 2048 字符。设置页 PATCH 时后端整体校验，非法值整批拒绝（422）。
  该 key 是破坏性重命名：旧目录 key 不再被读取、接受、别名或返回，无迁移路径；
  历史数据库可能保留一条惰性旧动态行，正常默认播种路径只创建新设置。
- 运行时配置暴露可选字段 `emoji_catalog_url`（`omitempty`）：未配置时字段缺省，
  客户端按未启用处理。
- 该端点返回 `Cache-Control: no-store`，避免浏览器或中间代理以旧缓存掩盖
  管理员的最新设置。
- Widget 在浏览器端以 `mode: cors`、`credentials: omit`、无 Referer、
  `cache: no-store` 拉取该目录；该远程文档不经后端代理、校验或缓存，因此
  该设置不会引入 SSRF 面。目录 JSON 采用 Furtalk 自有 emoji-pack 协议
  （根 `{packs:[...]}`，包类型 `unicode | emotion | image`；规范性契约见
  `docs/emoji-pack-protocol.md`）。
  选择 Unicode/颜文字项插入其原样 `content`；选择图片项插入 `:<id>:`。已发布评论
  中的已知图片 token 由 Widget 渲染为经校验的图片；未知 token 保持字面量。目录
  加载或解析失败只影响表情选择器，评论流程不受影响。本服务无内置表情数据：目录
  内容完全由部署者通过该 URL 提供并承担许可责任；未配置时 Widget 既不请求目录，
  也不渲染表情触发器。
- 自定义目录及其中图片由 Widget 访客的浏览器直接请求，受嵌入页面 CSP 与隐私
  策略约束，且图片宿主可见访客 IP；管理端帮助文案需披露该行为。

### 认证（/api/v1/auth）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | /api/v1/auth/email-codes | 发送邮箱验证码 |
| POST | /api/v1/auth/email-code/login | 邮箱验证码登录（请求体 `{email, code, captcha_token?}`） |
| POST | /api/v1/auth/password/login | 密码登录 |
| POST | /api/v1/auth/password/reset-codes | 请求密码重置验证码（对未知邮箱返回相同成功） |
| POST | /api/v1/auth/password/reset | 用验证码与新密码重置密码（重置后需重新登录） |
| POST | /api/v1/auth/logout | 登出 |
| POST | /api/v1/auth/passkeys/login/options | Passkey 登录 challenge |
| POST | /api/v1/auth/passkeys/login/verify | Passkey 登录校验 |
| GET | /api/v1/auth/providers | 可用 OAuth provider 列表 |
| GET | /api/v1/auth/oauth/{provider}/start | OAuth 启动（返回授权 URL） |
| POST | /api/v1/auth/oauth/{provider}/complete | OAuth 登录完成（JSON：`{state, code, error}` 或 `{handoff}`；成功返回 `{redirect}` 并写入会话/CSRF Cookie；一次性 state/handoff 即 CSRF 边界，无需第一方 CSRF） |

### 当前用户（/api/v1/me，RequireUser）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/v1/me | 当前用户资料 |
| PATCH | /api/v1/me | 更新资料 |
| PATCH | /api/v1/me/notification-preferences | 通知偏好 |
| POST | /api/v1/me/password | 首设/修改密码（已有密码时需 current_password；成功后重签当前浏览器会话与 CSRF Cookie） |
| POST | /api/v1/me/sessions/revoke | 注销全部设备（递增会话代次，使全部已签发 JWT 失效，清除当前 Cookie；账号安全页提供确认入口，成功后清空前端认证缓存并跳转登录） |
| POST | /api/v1/me/passkeys/options | Passkey 注册 challenge |
| POST | /api/v1/me/passkeys | 完成 Passkey 注册 |
| DELETE | /api/v1/me/passkeys/{passkey_id} | 删除 Passkey |
| PATCH | /api/v1/me/passkeys/{passkey_id} | 重命名 Passkey（请求体 `{name}`，204） |
| GET | /api/v1/me/identities | 绑定身份列表 |
| DELETE | /api/v1/me/identities/{identity_id} | 解绑身份 |
| GET | /api/v1/me/comments | 本人评论列表（页码分页；`{comments, total, user_delete_mode}`） |
| GET | /api/v1/me/comments/sites | 本人发表过评论的站点选项 |
| GET | /api/v1/me/comments/{comment_id} | 本人评论详情 |

### 评论（第一方，RequireUser）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | /api/v1/comments/{comment_id}/replies | 创建回复 |
| DELETE | /api/v1/comments/{comment_id} | 删除自己的评论 |

### 评论授权（RequireUser）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/v1/comment-authorizations/context | 只读授权上下文 `{site_id, site_name, origin}`（无写入；`origin` 为嵌入方精确 Origin，需命中站点白名单） |
| POST | /api/v1/comment-authorizations | 颁发 widget 授权码（请求体 `{site_id, origin, request_id}`；响应 `{code, request_id, expires_at}`） |

### Widget（公开，widget session / credential）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | /api/v1/widget/sites/{site_id}/runtime-config | 公开 | 站点运行时配置（含按 action 的公共 CAPTCHA 投影） |
| GET | /api/v1/widget/sites/{site_id}/comments | 公开（可选 widget credential） | 评论列表（`page_key` 必填；`sort=asc|desc|hot`，缺省用实例策略；置顶根评论先于普通评论、组内继续按所选排序；keyset 游标分页；响应含 `thread.comments_enabled`、`next_cursor`、每条评论 `is_pinned`、`like_count` 与查看者 `liked_by_me`） |
| GET | /api/v1/widget/sites/{site_id}/latest-comments | 公开 | 站点最新评论列表（默认 25，最大 25；按 `(created_at DESC, id DESC)` 排序，包含页面元数据） |
| POST | /api/v1/widget/sites/{site_id}/comments | 可选 widget credential | 统一评论创建：匿名普通邮箱单次提交；管理员邮箱无凭据时返回受控 `need_auth_code`（线程关闭时 409 `thread_closed`） |
| DELETE | /api/v1/widget/comments/{comment_id} | widget credential | 删除自己的评论 |
| PUT | /api/v1/widget/sites/{site_id}/comments/{comment_id}/like | widget credential | 点赞已发布评论（幂等），返回 `{comment_id, like_count, liked}` |
| DELETE | /api/v1/widget/sites/{site_id}/comments/{comment_id}/like | widget credential | 取消点赞已发布评论（幂等，计数不为负） |
| PUT | /api/v1/widget/sites/{site_id}/comments/{comment_id}/pin | 管理员 widget credential | 置顶已发布根评论（幂等），返回 `{comment_id, is_pinned}` |
| DELETE | /api/v1/widget/sites/{site_id}/comments/{comment_id}/pin | 管理员 widget credential | 取消根评论置顶（幂等），返回 `{comment_id, is_pinned}` |
| POST | /api/v1/widget/comment-authorizations/exchange | 公开 | 把一次性授权码兑换为 `widget_authenticated` 并写入 CHIPS Cookie |
| GET | /api/v1/widget/session | 公开（CHIPS cookie） | 会话探测 |
| DELETE | /api/v1/widget/session | 公开 | 清除会话 |

### 点赞（PUT/DELETE /widget/sites/{site_id}/comments/{comment_id}/like）

- 只有带有效 `widget_authenticated` 凭据的读者可点赞/取消；Like 归属该账号 user ID，
  绝不从请求 JSON 接受用户 ID。同一账号对同一评论最多一次（唯一约束兜底）。
- 只有 `published` 评论可点赞；缺失、未发布或隐藏状态返回与缺失一致的 404，不披露存在性。
- 重复添加/移除为幂等成功；返回权威 `{comment_id, like_count, liked}`。
- 软删除保留 Like；硬删除评论/用户通过复合外键级联清理 Like 行。
- 公开评论响应始终携带 `like_count`；`liked_by_me` 仅在有已验证查看者时反映其状态，
  匿名读取恒为 false，且绝不返回邮箱/IP/UA 或投票者列表。
- 匿名模式仅已有有效会话的管理员可点赞；普通访客只见只读计数。

### hot 排序

- `comment_sort` 动态设置与公开 `sort` 参数新增受控值 `hot`；管理/用户列表仍只接受
  `asc|desc`。hot 仅按评论自身 Like 计数降序，同计数按 `(created_at DESC, id DESC)`
  决胜，不聚合回复点赞、无时间衰减。
- hot 游标为版本化 `(like_count, created_at, id)` 编码，只能用于 hot；切换排序时
  丢弃旧游标与已加载行并重载第一页。

### 评论置顶（PUT/DELETE /admin/comments/{comment_id}/pin 与 Widget pin 路由）

- 置顶只允许管理员执行：后台使用 RequireAdmin，Widget 使用已验证且站点绑定的管理员
  凭据；普通用户、匿名访客、失效或跨站凭据均被拒绝。
- 只有根评论可以置顶，且从未置顶到置顶只接受 `published` 状态；回复和其他状态返回
  409。置顶与取消命令均幂等。
- 置顶根评论组整体位于未置顶评论之前，组内继续遵循 `asc`、`desc` 或 `hot` 的当前
  排序；不限制同一评论区的置顶数量，也不记录置顶时间或手工次序。
- 评论进入 `pending`、`spam` 或 `deleted` 时保留 `is_pinned`，公开读取仍只返回
  `published`；恢复发布后自动回到置顶组。管理员可对隐藏但仍存在的根评论取消置顶。
- Widget 只在已经探测到有效管理员 Widget 会话时，在根评论现有回复/点赞操作栏显示快捷
  操作，不新增管理员授权入口；所有访客仍能看到公开置顶标识。

### 统一评论创建与管理员保护（POST /api/v1/widget/sites/{site_id}/comments）

- 请求体 `{page_key, page_url?, page_title?, parent_id?, body_markdown, captcha_token, email, nickname, website_url?}`。
  `email` 与 `nickname` 必填：邮箱必须合法并规范化，用户邮箱保持不变；昵称去除
  首尾空白后必须非空且 ≤100 字符。`website_url` 为三态：字段缺省=保持当前网址、
  显式 `null`/空串=清空、合法非空 http(s) URL=覆盖。
- 每次成功创建评论都在同一事务内以请求昵称覆盖已解析用户的当前昵称，并应用网址
  三态操作；正文、页面、回复关系、线程状态、CAPTCHA、身份或资料任一校验失败时，
  均无资料写入、评论或事件副作用。事件只在事务提交后发布。
- 公开评论继续从对应用户记录投影昵称、网址、角色与头像。
- **匿名模式普通邮箱**：无需任何 Widget 凭据即可通过单次请求创建根评论或回复；
  未知邮箱按公开注册与邮箱域名策略解析或创建普通用户记录。普通邮箱、昵称与
  网址不可信，后一次成功提交可覆盖该邮箱对应普通用户的昵称与网址。
- **管理员邮箱保护**：规范化邮箱对应管理员时，请求必须携带有效的
  `widget_authenticated` 凭据，否则返回 `200 {"need_auth_code":true}`（该响应
  无任何写入副作用）。无有效凭据的管理员邮箱在注册关闭时仍返回该受控信号；
  该响应所含信息与 `need_auth_code` 一致，无额外细节。携带有效凭据时，主体必须
  为活跃管理员，站点、精确 Origin 与当前 credential epoch 必须匹配，且主体规范化
  邮箱与请求邮箱完全相同，否则整个请求被拒绝（含邮箱不匹配）。
- 认证模式：评论创建必须携带有效 `widget_authenticated` 凭据；请求邮箱仅用于
  一致性检查，主体邮箱保持不变。
- `widget_anonymous` JWT 已废弃，服务端已停止签发与接受；服务端会清除残留
  Cookie，普通匿名提交不受影响。

### 页面级评论开关（Thread 生命周期）

- Thread 由 `(site_id, page_key)` 唯一标识；`page_key` 是评论读取/创建的必填参数，
  空值或超过 512 字符返回 422 `invalid_input`。
- 公开读取缺失页面时惰性创建默认开启（`comments_enabled=true`）的唯一 Thread；
  重复读取复用该记录，无任何写入。
- `GET /widget/sites/{site_id}/comments` 响应的 `thread` 对象携带
  `comments_enabled`；公开 Widget 路由只输出该字段。
- Thread 关闭后，公开读取仍返回历史评论；创建入口（Widget 根评论、Widget 回复、
  第一方回复，含管理员身份）均被服务端拒绝，返回 409 `thread_closed`。
- 关闭后，评论所有者删除与管理员审核/编辑/删除/恢复均不受影响；全局
  `comment_mode`、审核、排序、通知与已签发 Widget 凭证保持不变。

### 管理端（/api/v1/admin，RequireAdmin）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/PATCH | /api/v1/admin/settings | 站点设置 |
| POST | /api/v1/admin/settings/legal-consent/reset | 显式递增协议同意版本（需要 CSRF；不修改协议链接） |
| GET/PUT | /api/v1/admin/providers | provider 列表/写入 |
| PUT/DELETE | /api/v1/admin/providers/{provider_key} | 更新/删除 provider |
| POST | /api/v1/admin/providers/{provider_key}/test | provider 连通性测试 |
| GET/POST | /api/v1/admin/sites | 站点列表/创建 |
| GET/PATCH/DELETE | /api/v1/admin/sites/{site_id} | 站点操作 |
| POST | /api/v1/admin/sites/{site_id}/origins | 添加 Origin（201 返回记录） |
| PATCH/DELETE | /api/v1/admin/sites/{site_id}/origins/{origin_id} | 更新/删除 Origin |
| GET | /api/v1/admin/sites/{site_id}/threads | 线程列表（按站点；可过滤 `comments_enabled`、搜索 `q`，页码分页） |
| PATCH | /api/v1/admin/sites/{site_id}/threads/{thread_id} | 更新线程元数据（请求体 `{page_key?, page_title?, comments_enabled?}` 至少一个字段；`page_title` 省略保持、显式 `null`/空白清空；`page_key` 站点内重复 409；缺省 422；跨站点 404） |
| DELETE | /api/v1/admin/sites/{site_id}/threads/{thread_id} | 删除线程（需 `confirm=true`；硬删除线程及其下全部评论，跨站点 404，204） |
| POST | /api/v1/admin/sites/{site_id}/threads/batch | 批量开启、关闭或硬删除评论区（`enable`、`disable`、`hard_delete`；当前页 ID，单批 1–100 个） |
| GET | /api/v1/admin/comments | 评论管理列表（页码分页；支持正文/作者邮箱/昵称 `q` 搜索） |
| GET | /api/v1/admin/comments/trend | 评论近 7/30 天按日趋势（管理员时区） |
| GET/PATCH/DELETE | /api/v1/admin/comments/{comment_id} | 管理评论（PATCH 编辑正文） |
| PUT/DELETE | /api/v1/admin/comments/{comment_id}/pin | 管理员置顶/取消置顶根评论（幂等） |
| POST | /api/v1/admin/comments/{comment_id}/publish | 发布 |
| POST | /api/v1/admin/comments/{comment_id}/pending | 移入待审核 |
| POST | /api/v1/admin/comments/{comment_id}/spam | 标记垃圾 |
| POST | /api/v1/admin/comments/{comment_id}/restore | 恢复 |
| POST | /api/v1/admin/comments/batch | 批量管理评论（`pending`、`publish`、`spam`、`soft_delete`、`restore`、`hard_delete`、`pin`、`unpin`；当前页 ID，单批 1–100 个） |
| GET | /api/v1/admin/users | 用户列表 |
| POST | /api/v1/admin/users | 预创建用户（资料、角色、可选初始密码、邮箱验证开关） |
| POST | /api/v1/admin/users/batch | 批量管理用户（`enable`、`disable`、`verify_email`、`unverify_email`、`soft_delete`、`hard_delete`、`restore`；当前页 ID，单批 1–100 个；不支持批量修改角色） |
| GET/PATCH/DELETE | /api/v1/admin/users/{user_id} | 用户操作（更新邮箱/昵称/网站/角色/状态/验证状态；DELETE 删除用户，`mode=soft\|hard` 缺省 soft，hard 需 `confirm=true`，无法删除自己或最后一名活跃管理员） |
| POST | /api/v1/admin/users/{user_id}/restore | 恢复软删除用户（仅恢复账号，不含评论） |
| POST | /api/v1/admin/users/{user_id}/password | 管理员重置目标用户密码 |
| POST | /api/v1/admin/smtp/test | SMTP 连通性测试 |

批量命令请求体为 `{ids:["12", "18"], action:"publish", confirm?:true}`，ID
必须是 1–100 个唯一的十进制字符串；软删除和硬删除都需要 `confirm=true`。
响应为 `{action, requested_count, changed_count, unchanged_count}`。所有目标在
一个数据库事务中按稳定顺序校验和写入，任一目标失败都会整批回滚并在统一错误
信封的 `details.failed_id` 中指出失败 ID；合法的同目标状态按幂等未变化计数。
批量发布事件仅在事务提交后为实际变更项发送。评论硬删除会先解除保留回复的
父/根引用，未选中的回复保持不变。

线程管理响应项包含十进制字符串 ID、站点名、页面标识、可空 URL/标题、
`comments_enabled` 与发现/更新时间。管理员可编辑 `page_key` 与 `page_title`
（修改不会改变线程 ID，也不会移动评论；修改 `page_key` 后，原值与线程的关联解除，
外部 Widget 以原值访问时按惰性解析语义可能创建新的空线程），也可以切换
评论开关。删除线程是破坏性操作：需 `confirm=true` 显式确认，硬删除线程及其
下全部评论；历史评论的正文归属无法修改。

评论区批量命令复用批量请求体与响应计数：`action` 仅允许 `enable`、`disable`、
`hard_delete`，后者必须携带 `confirm=true`。所有目标均在同一个数据库事务中按
稳定 ID 顺序校验和写入；同一开关状态计为 `unchanged`，缺失或跨站点 ID 在
`details.failed_id` 指出并回滚全部写入。硬删除会级联删除选中评论区下的全部评论。

### 第一方列表页码分页约定（评论/线程/用户/本人评论）

- 四个第一方列表（`GET /admin/comments`、`GET /admin/sites/{site_id}/threads`、
  `GET /admin/users`、`GET /me/comments`）统一使用页码分页：查询参数
  `page`（正整数，缺省 1）与 `limit`（缺省 25；用户列表默认 50，后端上限 100）。
  非正整数 `page`/`limit` 返回 400 `invalid_input`。
- 三个评论类列表响应携带与当前过滤/搜索条件一致的真实 `total`，用户列表携带
  `total`。前端按 `total` 计算总页数；越界页码返回空数组与真实总数。
- 管理员评论趋势使用 `GET /api/v1/admin/comments/trend?days=7&timezone=Asia%2FShanghai`。
  `days` 缺省为 7 且只允许 7 或 30；`timezone` 必须是有效 IANA 时区。响应包含
  `days`、规范化后的 `timezone` 与恰好对应数量的升序 `points`，每个点是该时区的
  `YYYY-MM-DD` 日历日和新建评论 `count`。统计按 `comments.created_at` 计算所有仍
  存在的状态，软删除仍计入，物理删除的行不再计入，缺失日期补零。
- 管理评论与线程按 `(created_at, id)` 确定性排序（受控 `sort=asc|desc`，缺省
  desc），用户列表按 `id` 排序，本人评论按 `(created_at, id)` 升序。
- 评论管理、线程管理与本人评论接口**无 `cursor` 查询参数，响应亦无
  `next_cursor`**；只有公开 Widget 评论读取保留 keyset 游标约定。

### 提供商配置与 CAPTCHA 选择（/api/v1/admin/providers、settings）

- CAPTCHA 与 OAuth/OIDC 使用不同的类型化语义：
  - CAPTCHA provider 通过 `PUT /admin/providers/{key}` 写入，请求体只含
    `kind` 与 `config`，**禁止携带 `enabled`**（携带返回 422）；多个 CAPTCHA provider
    可同时配置，互不覆盖。
  - OAuth/OIDC provider 写入保留 `enabled`，允许多个同时启用。
- 当前使用的 CAPTCHA provider 由公开设置 `captcha_provider` 选择：
  `PATCH /api/v1/admin/settings` 写入 `{key:"captcha_provider", type:"string", value:"<provider-key>"}`；
  空串表示未选择。切换选择只改变使用者，现有 CAPTCHA 配置保持不变。
  选择值必须指向已配置且可解密的 CAPTCHA provider，否则 PATCH 失败关闭（503）。
- `GET /admin/providers` 返回异类列表：CAPTCHA 项**省略 `enabled`**，
  OAuth/OIDC 项保留 `enabled`；各项均不含 secret/nonce/密文。
- 删除当前选中的 CAPTCHA provider 会同时清空 `captcha_provider` 选择；
  删除未选中的 provider 时，当前选择保持不变。

### 第三方登录提供商（OAuth/OIDC 固定预设与自定义）

- 固定内置 OAuth/OIDC provider 由后端只读 catalog（`internal/platform/oauth/catalog.go`）
  统一拥有 key、展示名、kind、注册模式、PKCE/nonce 能力、回调方式与配置 schema，
  是该矩阵的唯一事实来源；管理端 key/kind 校验、公开列表名称与登录注册策略均从该
  catalog 投影。未知 key 仍按自定义 OIDC 处理，自定义 OIDC 可重复创建。

| Key | 展示名 | Kind | 注册模式 | 管理端 public_config | 加密机密 | 实例要求 |
|---|---|---|---|---|---|---|
| `github` | GitHub | `oauth` | verified_email | `client_id`（固定 auth/token 端点） | `client_secret` | — |
| `google` | Google | `oidc` | verified_email | `client_id`（固定 Issuer） | `client_secret` | — |
| `gitlab` | GitLab | `oidc` | verified_email | `client_id`、`instance_url` | `client_secret` | 默认 `https://gitlab.com`，可改为自托管 HTTPS 实例（保留部署子路径） |
| `microsoft` | Microsoft | `oidc` | bind_only | `client_id` | `client_secret` | 固定 `common` authority，管理端无法配置租户 |
| `twitter` | Twitter | `oauth` | verified_email | `client_id` | `client_secret` | — |
| `gitea` | Gitea | `oidc` | verified_email | `client_id`、`instance_url` | `client_secret` | 必须显式配置 HTTPS 实例 |
| `apple` | Apple | `oidc` | verified_email | `client_id`（Services ID）、`team_id`、`key_id` | `private_key` | — |
| `discord` | Discord | `oauth` | verified_email | `client_id` | `client_secret` | — |
| `line` | LINE | `oidc` | bind_only | `client_id`（Channel ID） | `client_secret`（Channel Secret） | — |
| `mastodon` | Mastodon | `oauth` | bind_only | `client_id`、`instance_url` | `client_secret` | 必须显式配置 HTTPS 根 origin 实例（4.3+） |
| 自定义 | 任意 key | `oidc` | verified_email | `client_id`、`issuer_url`（HTTPS Issuer） | `client_secret` | — |

- **单实例语义**：每种内置 key 只允许存在一条配置；自定义别名、同类型重复
  条目与多实例均不允许。`gitlab` 默认 `https://gitlab.com`，`gitea` 与 `mastodon` 必须显式
  提供 HTTPS 实例；实例地址经服务端校验与规范化，授权/token/metadata/用户信息
  端点由该地址决定，与回调参数无关。自托管实例的远程 subject 按规范 issuer/实例
  隔离；更换实例后，此前绑定的 subject 将无法匹配，既有绑定失效。
- **注册模式是产品策略**（管理端无法修改）：
  - `verified_email`：GitHub、Google、GitLab、Twitter、Gitea、Apple、Discord 与
    自定义 OIDC。未绑定身份仅在适配器返回非空可信已验证邮箱时走现有邮箱匹配/
    注册路径；缺少可信邮箱时只能由已有 subject 绑定登录或已登录用户主动绑定。
  - `bind_only`：Microsoft、LINE、Mastodon。首次绑定只能由已登录用户完成；未绑定
    身份从登录/注册入口发起时返回通用失败；无用户创建，第三方邮箱亦不参与
    匹配或合并。
    外部 `verified_email` 存空字符串表示「该绑定未提供可信邮箱」，本地邮箱
    查询将其忽略（本地用户邮箱仍必填）。
- **机密处理**：`client_secret` 与 Apple `private_key` 均存入 AES-256-GCM
  envelope；新建必须提供对应机密，编辑缺省/空白原样复用现有 envelope（字节不变），
  非空才加密替换；Apple 的 `key_id` 与 `private_key` 作为一对原子轮换。删除是唯一
  清除机密的方式。机密不出现在任何读取接口、管理响应、公开列表与日志中。
- **回调方式**：第三方平台登记的 callback URL 指向**前端专用回调页**
  `https://<public-origin>/oauth/callback/{provider}`（同源部署：API 与 Web SPA
  共用同一公开 Origin）。provider 授权后浏览器先进入该前端页，再由前端调用
  `POST /api/v1/auth/oauth/{provider}/complete` 完成登录。普通 provider 由回调页
  直接提交 `{state, code, error}`；Apple 使用 `form_post` 把载荷 POST 到同一前端
  路径，由后端根路径桥创建短时一次性 `handoff` 后 303 到
  `/oauth/callback/apple?handoff=<opaque>`，前端再提交 `{handoff}`——授权码绝不
  进入任何 URL。`complete` 成功返回 `{redirect}`（已净化的站内回跳地址）并写入
  会话/CSRF Cookie；失败返回标准错误信封，state 有效时在 `details.redirect`
  携带回跳地址。一次性 state/handoff 即该流程的 CSRF 边界，**无需第一方 CSRF**；
  回调与桥均使用 `Cache-Control: no-store`。**部署时必须把每个启用 provider
  的 callback 白名单更新为新前端路由，与代码同步发布；旧
  `/api/v1/auth/oauth/{provider}/callback` 路由已完全移除。**

### 邮箱域名名单与 Gravatar 头像（/api/v1/admin/settings）

### 自动垃圾评论检测（spam provider）

- 垃圾检测在输入、权限、站点/线程与 CAPTCHA 门禁通过后、写事务开始前执行；
  外部网络调用与词库文件 IO 绝不进入数据库事务。
- 固定四个渠道与执行顺序，管理端不可排序：
  `spam.local` → `spam.akismet` → `spam.aliyun` → `spam.tencent`；渠道串行执行，
  首个 `pending`/`spam` 结果立即短路，后续渠道零调用。
- 渠道通过 `PUT /api/v1/admin/providers/{key}` 写入，请求体 `kind:"spam"` 且**必须
  携带 `enabled`**（缺失返回 422）。配置矩阵：

| Key | 公开配置 | 加密机密 | 判定 |
|---|---|---|---|
| `spam.local` | `file_path`（必填、可读词库文件）、`check_nickname`、`action` | 无 | 命中 → 按 `action` |
| `spam.akismet` | `action` | `api_key` | true → 按 `action`；false → 继续 |
| `spam.aliyun` | `region`（必填）、`biz_type` | `access_key_id`、`access_key_secret` | review → pending；block → spam |
| `spam.tencent` | `region`（必填）、`biz_type` | `secret_id`、`secret_key` | Review → pending；Block → spam |

- `action` 只允许 `pending`/`spam`，只出现在本地/Akismet 二元渠道。
- 外部渠道 Secret 组必须完整提交或整组留空：部分提交拒绝，整组空白保留现有
  envelope；`enabled=true` 必须同时满足公开配置与 Secret 完整。
- 本地词库只存绝对路径，不在数据库或管理 API 中传输完整词库；文件按行解析、
  忽略空行、去空白去重、Unicode 大小写不敏感匹配，`check_nickname` 开启时昵称
  也参与匹配；运行期按 size/mtime 热重载，失败保留最近成功快照。
- 作者当前角色为管理员时跳过全部检测器（根评论与回复均适用）；普通用户与匿名
  作者完整执行检测链。
- 单渠道失败、超时或返回未知结果按 unknown 降级并继续后续渠道；全部渠道通过或
  unknown 时沿用全局审核策略（`direct` → `published`、`review` → `pending`）。
- 数据外发边界：Akismet 送检完整评论上下文（站点 URL、IP、UA、页面链接、类型、
  昵称、邮箱、作者网址、正文）；阿里云/腾讯云只接收 Markdown 正文。启用 Akismet
  的控件旁持续显示敏感数据外发提示。
- `GET /admin/providers` 对 spam 项保留 `enabled` 与 `configured`；任何读取/日志
  不含 secret、nonce、密文或送检正文。



- 公开设置 `email_domain_whitelist` / `email_domain_blacklist`（json 数组，默认
  `[]`）与 `gravatar_base_url`（string，默认 `https://www.gravatar.com/avatar`）。
- 域名项忽略首尾空白与大小写，按规范化邮箱中 `@` 后的完整域名精确匹配；
  `example.com` 只精确命中自身，`badexample.com` 与 `sub.example.com` 均无匹配。
  非法域名（含 `@`/scheme/path/port/通配符/空标签）或规范化后重复的域名使整个
  PATCH 失败（422），批次内其他项不会生效。
- 白名单非空时仅精确命中白名单允许注册，黑名单无作用；白名单为空时黑名单
  精确命中拒绝；两者都为空时无限制。规则只约束新用户创建（邮箱验证码发送/
  验证码登录自动注册、OAuth/OIDC 未知邮箱自动注册、匿名 widget 会话创建），
  已存在账号、管理员预创建与首次初始化不受影响。
- 拒绝返回 422 `email_domain_not_allowed`，消息「该邮箱域名不允许注册」；
  该规则是公开策略，直接显式返回，属明确的域名策略错误而非凭据失败。
- `gravatar_base_url` 必须是绝对 http/https URL，不允许 userinfo、query 或
  fragment；生成时移除末尾 `/` 再追加 `/` 与规范化邮箱 trim+lower 的 SHA-256
  小写十六进制。
- 所有用户/评论/头像响应携带 `avatar_url` 字段（非空字符串）；规范化邮箱与
  独立哈希字段不在响应中暴露。

## 2. 响应约定

- 统一错误格式：`{"error": {"code", "message", "request_id", "details"}}`。
- `code` 为稳定机器可读标识；`message` 为中文文案。
- 状态码规则：400/401/403/404/409/422/429/500/503。
- `thread_closed`（409）在线程评论区关闭时由全部创建入口返回；公开读取不受影响。
- 授权码颁发/交换与 widget 会话探测响应使用 `Cache-Control: no-store`。
- 业务 ID 在 HTTP/JWT/JSON 边界为十进制字符串，内部 int64。
- 评论响应（公开、本人、管理视图）携带可空 `reply_to_user_id`（被回复者 id）与
  `reply_to_nickname`（被回复者当前昵称）：根评论两者为 `null`；回复未被硬删除的
  目标时昵称为当前资料值，目标账号硬删除后两者为 `null`，Widget 渲染
  「回复 已注销用户」。

## 3. 安全与身份约定

- JWT audiences/kinds：`first_party` / `widget_authenticated`；
  固定 HS256、issuer、audience、subject、kind 与时间声明校验。
  `widget_anonymous` 令牌已废弃，服务端已停止签发与接受。
- CHIPS cookie：`Secure; HttpOnly; SameSite=None; Partitioned; Path=/`，不含 Domain。
- Origin 精确匹配（无 wildcard/suffix/regex/null）； credentialed 请求禁止
  `Access-Control-Allow-Origin: *`。
- CORS 预检通过不代表授权；副作用请求必须重新校验 Origin。
- 认证/授权默认 deny；缓存/DB 读取错误 fail closed。
- 「邮箱是否存在」、authorization code 过期与已消费等敏感差异对客户端不可见。
- Bootstrap：无效/过期/已用 token 与已初始化实例均返回 410 `bootstrap_unavailable`。

### Widget 授权矩阵（模式感知，单一来源）

不同信任输入的闸门必须保持独立。Widget 只存在 `widget_authenticated` 评论凭据，
其主体在两种评论模式下的允许关系：

| 闸门 / 凭证 | 匿名模式普通用户 | 匿名模式管理员 | 认证模式普通用户 | 认证模式管理员 |
| --- | --- | --- | --- | --- |
| 匿名评论创建（无凭据） | 允许（注册开启时；未知邮箱自动注册） | 拒绝（返回受控 `need_auth_code`） | 拒绝（认证模式必须携带凭据） | 拒绝（认证模式必须携带凭据） |
| 第一方 popup 显式授权（签发授权码） | 拒绝 | 允许 | 允许 | 允许 |
| `widget_authenticated` 使用（评论/删除） | 拒绝 | 允许 | 允许 | 允许 |

- 所有行都要求主体活跃；未知模式/角色/状态/站点/Origin/epoch 均失败关闭。
- 管理员在两个已知角色间晋升/降级时，既有认证凭证保持不变；状态、模式、epoch、
  站点与 Origin 变化始终是实时授权检查。`widget_authenticated` 只提供站点绑定的
  评论者能力（含管理员邮箱保护下的评论创建与所有者删除），无法认证 `/admin` 或
  第一方 API，JWT claim 亦无任何管理员能力。
- 匿名模式普通用户无法登录第一方评论系统，也无法获得 Widget 凭据。

### Widget 资料行

- Widget 根编辑器常驻渲染一行资料（桌面为 昵称/邮箱/可选网站 三个横向轨道，窄宽
  响应式换行堆叠，顺序固定），始终直接可见、无折叠收纳，也没有独立的「保存资料」
  按钮。资料区自身无边框、圆角与内边距，评论编辑器外层边框与输入框边框不受影响。
- 浏览器保存说明仅在字段归一化发现无效输入时出现（文案「部分字段无效，
  不会用于评论身份。」）；正常资料无该提示。
- 点击「发表评论」时：规范化并校验可见资料字段（邮箱合法、昵称必填非空）→ 把接受的
  值存入站点作用域本地资料存储 → 发送单次评论创建请求（同时携带资料与正文）。
  匿名模式普通邮箱一次请求即完成，无需建立会话、无需资料 PATCH。

### 匿名邮箱提交

- 匿名模式中，普通访客可直接编辑邮箱/昵称/网址并提交评论；每次提交都以当次请求的
  昵称覆盖该邮箱对应普通用户的昵称并应用网址三态更新。普通邮箱、昵称与网址不可信，
  可能被他人冒用并覆盖——匿名提交不代表已验证身份。
- 管理员邮箱（匿名模式）无有效凭据时收到受控 `need_auth_code`；Widget 打开第一方
  授权 popup → 兑换 `widget_authenticated` → 用相同评论载荷重试。
- 残留的 `widget_anonymous` Cookie 无任何影响：评论流程按普通匿名提交处理，
  忽略该 Cookie。

### 认证资料锁定与双层登出

- 认证模式下尚未建立有效 authenticated Widget 会话时，资料字段保持可编辑（值只作为
  登录预填提示，第一方账号数据在登录后为权威）。
- 认证会话有效后，昵称、邮箱与网站均无法直接编辑，并显示「退出登录」按钮；退出
  Widget 登录后恢复可编辑。
- 退出按钮在同一用户手势中先发起 DELETE /api/v1/widget/session 清除当前顶层站点分区
  的 CHIPS Widget Cookie，再同步打开第一方 /logout 新标签页（保持浏览器 user
  activation）。两个会话处于不同 Cookie 上下文，结果独立：Widget 会话清除成功即把
  本地会话置为无效并解锁字段；失败时显示可恢复错误，不会显示已退出状态；新标签被拦截时
  提示主站尚未退出，并提供重新打开登出页的操作。

## 4. 数据库约定

- 表结构含复合外键约束 `(site_id, thread_id)`、`(site_id, parent_id)`、
  `(site_id, root_id)`，均指向 `UNIQUE (site_id, id)`。
- 评论软删除保留占位节点（非 `gorm.DeletedAt`）；垃圾、软删除与单条硬删除都只
  处理选中的评论，其回复保持原状态与正文。
- `comments.is_pinned` 为 `NOT NULL DEFAULT false`；数据库 CHECK 保证置顶行是持久化根评论
  （`parent_id IS NULL`、`root_id IS NULL` 且 `depth = 0`）。该字段与审核状态正交：隐藏评论可保留置顶状态，恢复发布后重新
  进入置顶组。
- `comments` 含 `reply_to_user_id` 列：可空、索引，指向 `users.id`，外键
  `ON DELETE SET NULL`。创建回复时写入被回复者的用户 ID；被回复者账号硬删除后
  该列被清空，回复继续保留并显示「回复 已注销用户」。
- 单条硬删除与用户硬删除在同一事务内先解除保留评论对目标评论的
  `parent_id` / `root_id` 引用，再删除目标行，避免复合外键级联误删回复；
  站点级删除仍通过 `ON DELETE CASCADE` 全量清空该站点全部 thread 与评论。
- 站点隔离：所有 site-owned 查询显式携带 `site_id`。
- SQLite 与 PostgreSQL 双方言 schema/约束一致。
- `threads` 的 `comments_enabled` 列：`NOT NULL`，默认 `true`；线程身份为
  `UNIQUE (site_id, page_key)`。
- 生产数据需保全：数据库使用版本化 migration，升级必须保持现有表结构可迁移。

## 5. 事件与通知约定

- 评论业务事务提交后再发布通知事件。
- 通知邮件 best-effort；无需 Kafka/RabbitMQ。
- 事件结构：`Published{CommentID, SiteID, ParentID, OccurredAt}`（comment 模块公开面）。

### 多通道管理员通知（8 个固定通道）

- 实例级通道：Telegram / Feishu / DingTalk / Bark / Slack / LINE / 通用 WebHook /
  Discord。每平台在一个实例中最多一个目标；按固定 key（`notification.*`）存入
  `dynamic_settings` 的 provider 行，复用 AES-256-GCM 密钥信封，无数据库迁移。
- 投递范围：仅消费 `comment.created`，且持久化状态为 `published`（新评论）或
  `pending`（评论待审核）；`spam` 与全部 `comment.published` 事件不投递到通道。
- 投递语义：best-effort、单次尝试、5s 有界超时、不重试、不持久化；多通道并发扇出，
  单通道失败只记录脱敏日志，不阻断其他通道与既有邮件。
- 管理接口：沿用 `/api/v1/admin/providers` CRUD/test。列表只返回固定 key、kind、
  `enabled`、`configured` 与公开元数据（Bark `server_url`），绝不返回机密或目标。
- 出站风险：Bark `server_url` 与通用 WebHook 允许 HTTP/HTTPS 与私网目标（受信管理员
  部署决策），拒绝 userinfo/fragment/非法 URL 且从不跟随重定向；Telegram/LINE 端点
  固定在代码中；Slack/Discord/Feishu/DingTalk webhook 要求 HTTPS 与官方主机/路径。
- 必填配置字段：Telegram（`bot_token`、`chat_id`）；Feishu/DingTalk/Slack/Discord
  （`webhook_url`）；Bark（`server_url` 公开、`device_key` 机密）；LINE
  （`channel_access_token`、`target_id`）；WebHook（`webhook_url`）。
  Feishu/DingTalk/WebHook 可选 `signing_secret`（缺省保留、`null` 清除、非空替换）。
- 平台错误只记录脱敏类别/错误码，绝不含 URL、凭据、目标或响应正文。

### 通用 WebHook v1 信封与签名

- 请求方法 POST；`Content-Type: application/json`；固定版本化 JSON 信封，
  业务 ID 全部编码为十进制字符串。
- 请求头：
  - `X-FurTalk-Webhook-Version: 1`（始终）
  - `X-FurTalk-Webhook-Timestamp: <unix-seconds>`（始终）
  - `X-FurTalk-Webhook-Signature: sha256=<lowercase-hex>`（仅配置签名密钥时）
- 签名：`signed_payload = "<unix-seconds>." + raw_body`，
  `signature = HMAC-SHA256(secret, signed_payload)`。签名输入与发送使用同一字节
  切片，绝不重新序列化；接收方应用常数时间比较。
- 事件与 `notification_type`：

  | event | notification_type | 场景 |
  |---|---|---|
  | `comment.created` | `new_comment` | 创建即 published |
  | `comment.created` | `pending_comment` | 创建即 pending |
  | `notification.test` | `test` | 管理员测试投递 |

- `event_id` 对单次创建事件确定（`comment.created:<site_id>:<comment_id>`），
  接收方可据此去重；FurTalk 本身不重试。
- 示例请求体（published 新评论）：

  ```json
  {
    "version": "1",
    "event": "comment.created",
    "notification_type": "new_comment",
    "event_id": "comment.created:12:34",
    "occurred_at": "2026-08-25T12:00:00Z",
    "site": {"id": "12", "name": "Example", "canonical_url": "https://example.com"},
    "page": {"thread_id": "56", "title": "Post title", "url": "https://example.com/post"},
    "comment": {"id": "34", "parent_id": null, "status": "published",
                "author_nickname": "Alice", "body_markdown": "Hello",
                "body_truncated": false, "created_at": "2026-08-25T12:00:00Z"}
  }
  ```

  缺失的 `parent_id` / `title` / `url` 序列化为 JSON `null`；测试事件
  （`notification.test`）请求体携带 `"test": true` 与 `message` 字段。

## 6. 约定校验方式

- `docs/swagger/swagger.json` 由源码注解生成；修改端点约定后须与源注解保持一致
  （drift 检查）。
- 端点实现的迁移必须保持路径、方法或鉴权要求不变。

## 7. Widget 授权前端约定（/authorize 与 /login）

> Widget 弹出一个未命名 popup 指向
> `/authorize`；授权、登录与返回都在同一个 popup 内完成，`window.opener` 全程保留
> （禁止使用 `noopener`，也禁止对该流程设置 `Cross-Origin-Opener-Policy: same-origin`）。

### /authorize URL

- `/authorize?site_id=<十进制字符串>&request_id=<base64url>`。
- URL 只携带授权请求：无 profile hints，亦无嵌入方 Origin 声明。
- `request_id` 为 Widget 用 Web Crypto 生成的 128-bit 以上随机值；`site_id` 必须为
  正十进制 int64，`request_id` 必须为 16–128 字符的 base64url，否则页面渲染
  「授权请求参数无效」并关闭。
- 页面要求存在可用的 `window.opener`；缺失时渲染「此页面需要从评论组件打开」并关闭。

### postMessage 协议

消息是版本化的判别对象，`type` 前缀固定为 `furtalk:`，所有消息都使用精确
`targetOrigin`，禁止 `*`：

| 消息 | 方向 | 负载 |
|---|---|---|
| `furtalk:authorization-init` | opener → popup | `{type, request_id, email?}` |
| `furtalk:authorization-ready` | popup → opener | `{type, request_id}` |
| `furtalk:authorization-success` | popup → opener | `{type, request_id, code}` |
| `furtalk:authorization-cancelled` | popup → opener | `{type, request_id}` |

- popup 只接受 `event.source === window.opener`、schema 合法且 `request_id` 与 URL
  一致的 `authorization-init`；嵌入方 Origin 以浏览器提供的 `MessageEvent.origin`
  为准，消息数据、URL 或 Referer 中的 Origin 字符串均无效力。可选 `email` 仅用于
  主站未登录时预填登录表单；授权主体与资料更新以实际登录会话为准。
- 只有显式点击「授权」按钮才会调用 POST /api/v1/comment-authorizations（body
  `{site_id, origin, request_id}`，带 CSRF 头），最后向 opener 精确 Origin 回发
  `furtalk:authorization-success {request_id, code}` 并 `window.close()`。
- 授权页不会根据 Widget 输入调用 PATCH /api/v1/me 更新昵称或网址；登录与注册
  流程也不会从 Widget 注入昵称或网址。最终授权主体始终来自实际第一方登录会话；
  登录其他邮箱时，禁止以提示邮箱修改账户或冒充其身份。
- 页面加载本身不会颁发授权码；「取消」回发 `furtalk:authorization-cancelled` 后关闭；
  用户直接关闭 popup 视为取消（由 Widget 侧观察窗口关闭）。

### popup sessionStorage pending 记录

- 键：`furtalk:authorization:<request_id>`；值：版本化 JSON
  `{version: 2, site_id, request_id, embedding_origin, email?, expires_at}`。
- 记录只存在于 popup 自己的 sessionStorage，10 分钟过期；成功 / 取消 / 过期后删除。
- 邮箱提示无 URL 传递，仅通过 postMessage 握手跨源，并在会话期间保存在
  sessionStorage。v1 格式（含昵称/网址）的记录视为无效。

### Widget 嵌入方 localStorage profile hints

- 键：`furtalk:profile:<service-origin>:<site_id>`（`<service-origin>` 为 Furtalk 服务
  Origin，`<site_id>` 为十进制字符串）；值：JSON
  `{email, nickname, website_url}`。
- 只存在于嵌入方自己的 Origin 的 localStorage；Furtalk 页面无法直接读取嵌入方
  Web Storage。一个嵌入方 Origin 无法读取另一个 Origin 的存储。
- 仅保存用户手动输入的邮箱 / 昵称 / 网站 URL；评论草稿与凭据除外。
- 存储失败（隐私模式、配额、权限）时组件降级为内存存储，行为不变。

### Widget 会话 Cookie（CHIPS）

- 名称：`__Host-furtalk_widget`；属性
  `Secure; HttpOnly; SameSite=None; Partitioned; Path=/`，不含 Domain。
- 会话探测 `GET /api/v1/widget/session` 返回 `valid` / `credential_mode` /
  `user_id`；`valid=false`（浏览器禁用 CHIPS / 第三方 Cookie 时）组件展示可恢复的
  「浏览器不支持评论会话」状态，不会静默降级。

### 嵌入脚本

- 主站托管 ES module：`<script type="module" src="https://<furtalk>/widget/furtalk.js">`；
  脚本 Origin 默认从 `import.meta.url` 推导，可用 `service-origin` 属性覆盖（开发 /
  CDN 布局）。
- 挂载：`<furtalk-comments site-id="<十进制>" page-key="<页面键>"></furtalk-comments>`。
  `page-key` 必填；特殊值 `location` 由 `location.pathname + location.search` 推导。
  `page-url` / `page-title` 可选，默认取宿主页面文档值。
- 元素使用 Shadow DOM，全部样式在 Shadow 内部；主题仅通过文档化的 CSS custom
  properties（`--furtalk-*`）暴露。

### /login 授权流程标记

- 授权 popup 在会话探测返回 401 时，同一窗口导航到
  `/login?authorize=1&redirect=<url-encoded /authorize?...>`。
- `authorize=1` 时登录页从 popup sessionStorage 读取 pending 记录的邮箱提示预填
  登录表单；邮箱提示仅用于预填，与资料写入、注册无关。
- 所有登录方式（密码、Passkey、OAuth、邮箱验证码）都保留该本地
  `/authorize?...` 回跳；登录成功后回到授权页继续。
- 邮箱验证码登录请求体 `{email, code, captcha_token?}` 中无昵称或网址提示；
  登录与注册流程也不会从 Widget 注入昵称或网址。

### 第一方 /logout 页面

- 第一方 `/logout` 页面无回跳地址参数；凭据、邮箱与账户资料不经 URL 或
  `postMessage` 传递，亦无开放重定向。
- 页面挂载后自动调用 `POST /api/v1/auth/logout`（Web API 客户端附加 CSRF 头），
  清除第一方会话与 CSRF Cookie，并清空前端缓存的会话数据。
- 成功后显示成功结果并尝试 `window.close()` 关闭由 Widget 打开的标签页；浏览器拒绝
  自动关闭时保留成功页面作为回退。失败时显示错误与重试按钮，不会显示已退出状态。
