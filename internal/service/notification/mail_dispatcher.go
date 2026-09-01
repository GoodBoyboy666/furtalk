package notification

import (
	"context"
	"sync"
	"sync/atomic"

	"furtalk/internal/platform/mailer"
)

const (
	mailRecipientLimit = 100
	mailWorkerCount    = 4
	mailQueueCapacity  = 256
)

type mailJob struct {
	ctx          context.Context
	userID       int64
	message      mailer.Message
	unsub        string
	htmlHasUnsub bool
}

type mailSubmitter func(mailJob) bool

// mailDispatcher bounds notification mail fan-out and owns its worker lifecycle.
type mailDispatcher struct {
	queue   chan mailJob
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	dropped atomic.Uint64
}

func newMailDispatcher(ctx context.Context, deliver func(mailJob)) *mailDispatcher {
	workerCtx, cancel := context.WithCancel(ctx)
	d := &mailDispatcher{
		queue:  make(chan mailJob, mailQueueCapacity),
		cancel: cancel,
	}
	d.wg.Add(mailWorkerCount)
	for i := 0; i < mailWorkerCount; i++ {
		go func() {
			defer d.wg.Done()
			for {
				select {
				case <-workerCtx.Done():
					return
				case job := <-d.queue:
					deliver(job)
				}
			}
		}()
	}
	return d
}

func (d *mailDispatcher) submit(job mailJob) bool {
	if d == nil {
		return false
	}
	select {
	case d.queue <- job:
		return true
	default:
		d.dropped.Add(1)
		return false
	}
}

func (d *mailDispatcher) stop() {
	if d == nil {
		return
	}
	d.cancel()
	d.wg.Wait()
}

func (d *mailDispatcher) droppedCount() uint64 {
	if d == nil {
		return 0
	}
	return d.dropped.Load()
}
