package notification

import (
	"context"
	"sync"
	"sync/atomic"

	"furtalk/internal/platform/mailer"
)

// 邮件分发器的队列与并发限制常量。
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

// mailDispatcher 限制通知邮件并发量并管理工作协程生命周期。
type mailDispatcher struct {
	queue   chan mailJob
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	dropped atomic.Uint64
}

// newMailDispatcher 构建邮件分发器。
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

// submit 提交邮件任务。
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

// stop 停止邮件分发器。
func (d *mailDispatcher) stop() {
	if d == nil {
		return
	}
	d.cancel()
	d.wg.Wait()
}

// droppedCount 读取被丢弃的邮件任务数。
func (d *mailDispatcher) droppedCount() uint64 {
	if d == nil {
		return 0
	}
	return d.dropped.Load()
}
