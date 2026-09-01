// Command Furtalk 后端的进程入口。
// 负责启动失败日志与运行单一 *fx.App；全部装配、信号与退出码
// 生命周期由 internal/app.New / *fx.App.Run 管理。
//
// @title Furtalk
// @version 1.0.0
// @description Furtalk 评论系统
package main

import (
	"flag"
	"os"

	"furtalk/internal/app"
	"furtalk/internal/platform/logging"
)

func main() {
	web := flag.Bool("web", false, "serve the embedded Web console")
	flag.Parse()

	application, err := app.New(app.WithWeb(*web))
	if err != nil {
		logging.New(os.Stderr).Error("startup failed", logging.Error(err))
		os.Exit(1)
	}
	// Fx 处理 SIGINT/SIGTERM 与退出码：正常关闭返回，致命错误以非零码退出。
	application.Run()
}
