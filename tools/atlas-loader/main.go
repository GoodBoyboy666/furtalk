// Command atlas-loader 以 Atlas GORM Program Mode 输出 furtalk 的期望 schema。
// 它是独立工具模块，只供 atlas.hcl 的 external schema 数据源调用，不进入
// 应用运行依赖图。用法：go run -mod=readonly . <sqlite|postgres>。
package main

import (
	"fmt"
	"os"

	"ariga.io/atlas-provider-gorm/gormschema"
	"furtalk/internal/repository/model"
)

const usage = "usage: atlas-loader <sqlite|postgres>"

func main() {
	if len(os.Args) != 2 {
		fail(usage)
	}
	switch os.Args[1] {
	case "sqlite", "postgres":
	default:
		fail("unsupported dialect %q; %s", os.Args[1], usage)
	}
	ddl, err := gormschema.New(os.Args[1]).Load(model.All()...)
	if err != nil {
		fail("load %s schema: %v", os.Args[1], err)
	}
	fmt.Print(ddl)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
