# Atlas Versioned migration 项目配置。
# 两个环境各自持有独立方言的期望 schema、dev database 与 migration 目录，
# 双方言版本历史相互独立。目标业务库 URL 绝不写入本文件：inspect/diff/validate
# 只读 desired schema 与 dev database，apply 由运维在外部显式指定 --url。
#
# 期望 schema 是 tools/atlas-loader 从 model.All() 生成的方言 SQL（atlas/schema.*.sql）。
# 修改 GORM 模型后必须先用 loader 重新生成对应 SQL 文件，再运行 migrate diff。

env "sqlite" {
  src = "file://atlas/schema.sqlite.sql"
  # 内存 dev database；_fk=1 让 Atlas 解析外键约束。
  dev = "sqlite://file?mode=memory&_fk=1"
  migration {
    dir = "file://migrations/sqlite"
  }
}

env "postgres" {
  src = "file://atlas/schema.postgres.sql"
  # 专用可写 dev database，由命令时注入，绝不入库。
  dev = getenv("ATLAS_POSTGRES_DEV_URL")
  migration {
    dir = "file://migrations/postgres"
  }
}
