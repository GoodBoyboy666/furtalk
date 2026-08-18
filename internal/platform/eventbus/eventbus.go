// Package eventbus 提供非阻塞的进程内事件总线，用于异步解耦。
// 队列已满或总线关闭时 Publish 返回 ErrDropped，事件只以净化后的形式记录。
// 总线与具体类型无关，不含业务策略；事件类型由使用方定义。
package eventbus

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"furtalk/internal/platform/logging"
)

// DefaultCapacity 是未指定容量时使用的有界队列大小。
const DefaultCapacity = 1024

// ErrDropped 在队列已满或总线已关闭时由 Publish 返回。发布是尽力而为的，不会阻塞使用方。
var ErrDropped = errors.New("eventbus: event dropped")

// Bus 是携带具体事件类型 T 的有界非阻塞事件队列。发布不会阻塞。
type Bus[T any] struct {
	queue chan T
	log   *slog.Logger
	done  chan struct{}
	once  sync.Once
}

// New 以给定容量创建有界总线；非正数容量使用 DefaultCapacity。
// nil logger 由统一模块规范化为 discard logger。
func New[T any](capacity int, log *slog.Logger) *Bus[T] {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	log = logging.Normalize(log)
	return &Bus[T]{queue: make(chan T, capacity), log: log, done: make(chan struct{})}
}

// Publish 将事件入队且不阻塞。
// 成功返回 nil；队列已满或总线关闭时返回 ErrDropped，并记录一条净化后的日志。
// 使用方只在业务事务提交后调用。
func (b *Bus[T]) Publish(ev T) error {
	select {
	case <-b.done:
		return ErrDropped
	default:
	}
	select {
	case b.queue <- ev:
		return nil
	default:
		b.log.Warn("eventbus: event dropped")
		return ErrDropped
	}
}

// Consume 阻塞并处理事件，直到 ctx 被取消或总线关闭。
// 返回 nil；总线关闭时待处理事件被丢弃，尽力而为语义不变。
// 这是可取消的阻塞消费者，适合由生命周期管理的后台任务驱动。
func (b *Bus[T]) Consume(ctx context.Context, fn func(T)) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-b.done:
			return nil
		case ev := <-b.queue:
			fn(ev)
		}
	}
}

// Close 停止总线。待处理事件被丢弃；此后的 Publish 返回 ErrDropped。
// Close 幂等。
func (b *Bus[T]) Close() {
	b.once.Do(func() { close(b.done) })
}
