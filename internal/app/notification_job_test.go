package app

import (
	"context"
	"testing"

	"furtalk/internal/service/notification"
)

// TestProvideNotificationJobIndependentOfSMTP 验证通知消费任务不依赖 SMTP 配置：
// 即使 SMTP 缺失（mailer=nil），只要事件总线存在仍贡献通知消费者。
func TestProvideNotificationJobIndependentOfSMTP(t *testing.T) {
	svc := &services{notifications: notification.NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "", nil)}
	got := provideNotificationJob(svc)
	if len(got.Jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(got.Jobs))
	}
	if got.Jobs[0].Name != "notification-consumer" {
		t.Fatalf("job name = %q, want notification-consumer", got.Jobs[0].Name)
	}
	// nil bus 时 Run 惰性返回 nil，任务可被监管器安全运行。
	if err := got.Jobs[0].Run(context.Background()); err != nil {
		t.Fatalf("run with nil bus = %v, want nil", err)
	}
}
