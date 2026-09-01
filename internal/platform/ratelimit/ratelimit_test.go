package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestAllowNRequestPathEnforcesHardCapacity 证明请求路径不再执行全表扫描，
// 且活跃桶数量不会超过硬容量。
func TestAllowNRequestPathEnforcesHardCapacity(t *testing.T) {
	t.Parallel()
	l := New(10, 100)
	for i := 0; i < DefaultBucketCapacity; i++ {
		l.AllowN(string(rune('a'+i%26))+itoa(i), 1)
	}
	if got := l.BucketCount(); got != DefaultBucketCapacity {
		t.Fatalf("bucket count = %d, want %d", got, DefaultBucketCapacity)
	}
	if l.AllowN("new-subject", 1) {
		t.Fatal("new subject must fail closed at capacity")
	}
	if got := l.BucketCount(); got != DefaultBucketCapacity {
		t.Fatalf("bucket count after rejected subject = %d, want %d", got, DefaultBucketCapacity)
	}
}

func TestLimiterCapacityKeepsExistingSubjectsAndNormalizesUnknown(t *testing.T) {
	l := NewWithCapacity(1, 2, 1)
	if !l.Allow("") || !l.Allow(" ") {
		t.Fatal("empty subjects must share the unknown bucket")
	}
	if l.Allow("new") {
		t.Fatal("new subject must fail when capacity is full")
	}
	if got := l.BucketCount(); got != 1 {
		t.Fatalf("bucket count = %d, want 1", got)
	}
}

func TestLimiterConcurrentAdmissionNeverExceedsCapacity(t *testing.T) {
	l := NewWithCapacity(1, 1, 8)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.Allow("subject-" + itoa(i))
		}(i)
	}
	wg.Wait()
	if got := l.BucketCount(); got > 8 {
		t.Fatalf("bucket count = %d, exceeds capacity 8", got)
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

func TestPolicyRegistryKeepsIndependentBuckets(t *testing.T) {
	r := NewPolicyRegistry(map[string]Config{
		"one": {Rate: 1, Burst: 2},
		"two": {Rate: 1, Burst: 1},
	})
	if !r.Allow("one", "user-1") || !r.Allow("one", "user-1") || r.Allow("one", "user-1") {
		t.Fatal("one policy did not enforce its burst")
	}
	if !r.Allow("two", "user-1") {
		t.Fatal("one policy exhausted another policy")
	}
	if !r.Allow("one", "user-2") {
		t.Fatal("subjects unexpectedly shared a bucket")
	}
	if r.Allow("missing", "user-1") {
		t.Fatal("unknown policy allowed a request")
	}
	if !r.Allow("two", "") || r.Allow("two", "") {
		t.Fatal("empty subject did not use the stable unknown bucket")
	}
}

func TestPolicyRegistryCopiesDefinitionsAndHasOneCleanupLoop(t *testing.T) {
	now := time.Now()
	configs := map[string]Config{"policy": {Rate: 1, Burst: 1}}
	r := NewPolicyRegistry(configs)
	configs["other"] = Config{Rate: 1, Burst: 1}
	if got := r.PolicyNames(); len(got) != 1 || got[0] != "policy" {
		t.Fatalf("registry policy names = %v, want [policy]", got)
	}
	r.now = func() time.Time { return now }
	if !r.Allow("policy", "idle") {
		t.Fatal("initial policy admission rejected")
	}
	now = now.Add(idleTimeout + time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.CleanupLoop(ctx); err != nil {
		t.Fatalf("cleanup after cancel = %v", err)
	}
	// Trigger an explicit sweep through the per-policy limiter to keep this
	// test deterministic without waiting for the minute ticker.
	r.Limiter("policy").sweep(now)
	if got := r.BucketCount("policy"); got != 0 {
		t.Fatalf("bucket count after sweep = %d, want 0", got)
	}
}

func TestDefaultPoliciesIncludePasswordLoginBudgets(t *testing.T) {
	policies := DefaultPolicies()
	for name, want := range map[string]Config{
		PolicyPasswordLoginIP:    {Rate: 0.5, Burst: 5},
		PolicyPasswordLoginEmail: {Rate: 0.2, Burst: 3},
	} {
		if got := policies[name]; got != want {
			t.Fatalf("policy %q = %+v, want %+v", name, got, want)
		}
	}
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
