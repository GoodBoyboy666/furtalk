// Command furtalk 是 Furtalk 后端的进程入口。
// 它只负责启动失败日志与运行单一 *fx.App；全部装配、信号与退出码
// 生命周期都由 internal/app.New / *fx.App.Run 管理。
//
// @title Furtalk API
// @version 1.0.0
// @description Furtalk 评论系统的 HTTP API：覆盖站点与管理员引导、
// @description 第一方与 widget 认证/会话、评论发布与审核、站点/用户/设置/
// @description 提供商管理与邮件通知退订。
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
