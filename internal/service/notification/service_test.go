package notification

import (
	"context"
	"testing"
	"time"

	"furtalk/internal/domain"
	"furtalk/internal/platform/eventbus"
	"furtalk/internal/platform/mailer"
)

type fakeMailer struct{}

func (fakeMailer) Send(ctx context.Context, msg mailer.Message) error { return nil }

// TestRunLazyWhenUnconfigured 证明 mailer/bus 缺失时消费惰性返回 nil。
func TestRunLazyWhenUnconfigured(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "", nil)
	if err := svc.Run(context.Background()); err != nil {
		t.Fatalf("lazy Run must return nil, got %v", err)
	}
}

// TestRunBlocksUntilCancel 证明配置完成后 Run 是阻塞、可取消的受管消费者。
func TestRunBlocksUntilCancel(t *testing.T) {
	bus := eventbus.New[domain.CommentEvent](4, nil)
	svc := NewService(nil, nil, nil, nil, nil, nil, bus, fakeMailer{}, nil, nil, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()

	select {
	case <-done:
		t.Fatal("Run returned before cancellation")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}
