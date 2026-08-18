package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestAllowNRequestPathDoesNotSweep 证明请求路径不再执行全表扫描：
// 超过旧阈值数量的活跃桶后，桶数量保持增长而不是被同步清理。
func TestAllowNRequestPathDoesNotSweep(t *testing.T) {
	t.Parallel()
	l := New(10, 100)
	// 超过旧 sweepThreshold（10000）只插入桶，不触发清理。
	for i := 0; i < 10100; i++ {
		l.AllowN(string(rune('a'+i%26))+itoa(i), 1)
	}
	if got := l.BucketCount(); got != 10100 {
		t.Fatalf("bucket count = %d, want 10100 (request path must not sweep)", got)
	}
}

// TestCleanupLoopRemovesIdleBuckets 证明后台清理删除空闲桶并保留活跃桶。
func TestCleanupLoopRemovesIdleBuckets(t *testing.T) {
	t.Parallel()
	now := time.Now()
	l := New(10, 100)
	l.now = func() time.Time { return now }

	l.AllowN("active", 1)
	l.AllowN("idle", 1)

	// 让 idle 桶过期，active 桶保持新鲜。
	now = now.Add(idleTimeout + time.Minute)
	l.AllowN("active", 1)

	l.sweep(l.now())
	if got := l.BucketCount(); got != 1 {
		t.Fatalf("bucket count after sweep = %d, want 1", got)
	}
	// 清除剩余桶，避免对后续测试产生副作用。
	l.sweep(now.Add(idleTimeout + time.Minute))
}

// TestCleanupLoopStopsOnCancel 证明 ctx 取消后清理循环立即返回。
func TestCleanupLoopStopsOnCancel(t *testing.T) {
	t.Parallel()
	l := New(10, 100)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.CleanupLoop(ctx); err != nil {
		t.Fatalf("CleanupLoop after cancel err = %v, want nil", err)
	}
}

// TestCleanupLoopConcurrentSafe 证明清理与请求并发执行不产生竞态。
func TestCleanupLoopConcurrentSafe(t *testing.T) {
	l := New(10, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = l.CleanupLoop(ctx)
	}()

	for i := 0; i < 100; i++ {
		l.AllowN("key-"+itoa(i), 1)
	}
	cancel()
	wg.Wait()
}

// itoa 是测试用的小整数转字符串（不依赖 strconv）。
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := "0123456789"
	buf := make([]byte, 0, 8)
	for i > 0 {
		buf = append([]byte{digits[i%10]}, buf...)
		i /= 10
	}
	return string(buf)
}
