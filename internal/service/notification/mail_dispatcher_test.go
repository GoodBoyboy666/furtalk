package notification

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestMailDispatcherUsesAtMostFourWorkersAndDropsWithoutBlocking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, mailWorkerCount)
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	var startCount atomic.Int32
	d := newMailDispatcher(ctx, func(mailJob) {
		current := active.Add(1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		if startCount.Add(1) <= mailWorkerCount {
			started <- struct{}{}
		}
		<-release
		active.Add(-1)
	})

	for i := 0; i < mailWorkerCount; i++ {
		if !d.submit(mailJob{}) {
			t.Fatal("initial worker job was dropped")
		}
	}
	for i := 0; i < mailWorkerCount; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("worker did not start")
		}
	}

	start := time.Now()
	for i := 0; i < mailQueueCapacity+32; i++ {
		d.submit(mailJob{})
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("submitting to a full queue blocked for %s", elapsed)
	}
	if got := len(d.queue); got > mailQueueCapacity {
		t.Fatalf("queue length = %d, exceeds %d", got, mailQueueCapacity)
	}
	if d.droppedCount() == 0 {
		t.Fatal("full queue did not record a drop")
	}

	close(release)
	d.stop()
	if got := maximum.Load(); got > mailWorkerCount {
		t.Fatalf("maximum concurrent workers = %d, want <= %d", got, mailWorkerCount)
	}
}

func TestMailDispatcherStopsWorkersOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := newMailDispatcher(ctx, func(mailJob) {})
	cancel()
	d.stop()
	if got := d.droppedCount(); got != 0 {
		t.Fatalf("unexpected dropped jobs = %d", got)
	}
}
