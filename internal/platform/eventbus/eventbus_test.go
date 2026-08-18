package eventbus

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestConsumeProcessesEvents(t *testing.T) {
	bus := New[int](4, testLogger())
	var mu sync.Mutex
	var got []int
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- bus.Consume(ctx, func(ev int) { mu.Lock(); got = append(got, ev); mu.Unlock() }) }()

	for i := 1; i <= 3; i++ {
		if err := bus.Publish(i); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	if len(got) != 3 {
		t.Fatalf("consumed %d events, want 3", len(got))
	}
	mu.Unlock()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("consume did not return after cancel")
	}
}

func TestConsumeReturnsOnCancel(t *testing.T) {
	bus := New[int](4, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bus.Consume(ctx, func(int) {}) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("consume did not return after cancel")
	}
}

func TestConsumeReturnsOnClose(t *testing.T) {
	bus := New[int](4, testLogger())
	done := make(chan error, 1)
	go func() { done <- bus.Consume(context.Background(), func(int) {}) }()
	bus.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("consume did not return after close")
	}
	if err := bus.Publish(1); !errors.Is(err, ErrDropped) {
		t.Fatalf("Publish after close = %v, want ErrDropped", err)
	}
}
