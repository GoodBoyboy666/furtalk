# Furtalk Emoji Pack 协议

> 创建：2026-08-22
> 本文档面向 Furtalk 的接入方与维护开发者，定义远程表情目录（emoji-pack）的规范契约：
> 目录 JSON 结构、标识符与值约束、图片源规则、Picker 插入语义与 Renderer 渲染语义。

Furtalk 本身不发行或内置任何表情数据。表情目录由部署者通过实例级动态设置
`emoji_catalog_url`（公开 string，默认 `""`，必须是绝对 HTTPS URL）提供，并由
提供方承担内容的许可与安全责任。

## 1. Json结构

目录根必须是**恰好一个对象**，且只含一个 `packs` 数组：

```json
{
  "packs": [
    {
      "id": "emoji",
      "name": "Emoji",
      "type": "unicode",
      "items": [
        { "id": "joy", "name": "笑哭", "content": "😂" },
        { "id": "heart", "name": "红心", "content": "❤️" }
      ]
    },
    {
      "id": "face",
      "name": "颜文字",
      "type": "emotion",
      "items": [
        { "id": "shrug", "name": "摊手", "content": "¯\\_(ツ)_/¯" }
      ]
    },
    {
      "id": "aru",
      "name": "阿鲁",
      "type": "image",
      "items": [
        { "id": "happy", "name": "开心", "src": "/emoji/aru/happy.webp" }
      ]
    }
  ]
}
```

包类型是封闭枚举，只允许 `unicode | emotion | image`：

- `unicode` 与 `emotion` 包：用于 Unicode 表情与颜文字（文本表情）。
- `image` 包：用于图片表情，插入与渲染都基于其稳定的 `id`。

## 2. 类型契约

```ts
interface EmojiPackDocument {
  packs: EmojiPack[]
}

type EmojiPack = UnicodePack | EmotionPack | ImagePack

interface UnicodePack {
  id: string
  name: string
  type: 'unicode'
  items: TextEmojiItem[]
}

interface EmotionPack {
  id: string
  name: string
  type: 'emotion'
  items: TextEmojiItem[]
}

interface ImagePack {
  id: string
  name: string
  type: 'image'
  items: ImageEmojiItem[]
}

interface TextEmojiItem {
  id: string
  name: string
  content: string
}

interface ImageEmojiItem {
  id: string
  name: string
  src: string
}
```

一个包必须恰好包含 `id`、`name`、`type`、`items` 四个字段。一个 `unicode` 或
`emotion` 包中的项必须恰好包含 `id`、`name`、`content` 三个字段，不得携带 `src`；
一个 `image` 包中的项必须恰好包含 `id`、`name`、`src` 三个字段，不得携带 `content`。
未知包类型、缺失字段、字段类型错误与多余字段都会使**整个文档被拒绝**，不存在
部分包的降级回退。

## 3. 标识符与值规则

- 包 id 与项 id：1–64 个 ASCII 字符，匹配 `^[a-z0-9][a-z0-9_-]*$`。
- 包 name：去除首尾空白后 1–64 个 Unicode 码点。
- 项 name：去除首尾空白后 1–128 个 Unicode 码点。
- 文本 `content`：1–256 个 Unicode 码点。其值会被原样插入，周边空白有意义，
  归一化时**不得 trim**。
- id、name、content 均拒绝 NUL、CR/LF、C0/C1 控制字符与 raw HTML 标签形态
  （`<` 紧跟字母、`/`、`!` 或 `?`）。name 只是标签，永不作为标记渲染。
- 包 id 在包之间唯一；项 id 在**整个文档的所有项中全局唯一**，使 `:<id>:` 始终
  只有一个确定含义。

### 文档防御性上限

| 维度 | 上限 |
|---|---|
| 响应字节数 | 512 KiB |
| 包数量 | 32 |
| 每包项数 | 256 |
| 总项数 | 1024 |

## 4. 图片源规则

- `src` 是非空 URL 引用，长度不超过 2048 字符。
- 相对路径（包括 `/emoji/...`）基于目录**最终响应 URL（重定向后）**解析。
- 解析结果必须使用 HTTPS、具有非空 host。
- 非法或不安全的图片源会使整个Json被拒绝。

## 5. Picker 插入语义

- 选中 `unicode` 或 `emotion` 项：在当前选区插入该项的**原样 `content`**。
- 选中 `image` 包中 id 为 `happy` 的项：插入字面量文本 `:happy:`。
- Picker 永不插入图片 HTML 或 Markdown 图片语法。
- 插入会替换当前选区、保留周边文本、只更新所属（根或回复）composer 的草稿、
  恢复焦点并把折叠光标置于插入值之后。

## 6. Renderer 渲染语义

- Picker 与 Renderer 消费**同一份**成功归一化的目录快照。
- Renderer 只从 `image` 包的项构建 token 查找表。
- 普通评论文本中，已知 token（如 `:happy:`）渲染为一张图片：`src` 为归一化后的
  项 URL，可访问名称为项 `name`。
- `unicode`/`emotion` 包的项 id 与未知 token 保持字面量文本。
- 行内代码、围栏代码、Markdown 链接/图片目标中的 token 保持字面量，不被改写。
- 渲染出的表情图片使用懒加载、异步解码与 no-referrer 策略；目录中的 raw HTML
  永不接受或拼接。
- 目录缺失、加载中、非法或失败时，所有 token 保持字面量，评论阅读与撰写照常可用。

## 7. 加载与安全边界

- Widget 以 `mode: cors`、`credentials: omit`、`referrerPolicy: no-referrer`、
  `cache: no-store` 发起目录请求，绝不携带 Furtalk Cookie、凭据或 Referer。
- 请求有超时、响应字节上限与 stale 请求取消；重定向离开 HTTPS 时整个Json被拒绝。
- 目录加载或解析失败只影响表情选择器（展示错误与重试），评论工作流不受影响。
- `widget/src/emoji.ts` 是唯一从 raw `unknown` JSON 到受控目录类型的解码边界；
  UI 与渲染代码不直接读取远程负载字段。
