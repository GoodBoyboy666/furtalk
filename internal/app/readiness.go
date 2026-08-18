package app

import "sync/atomic"

// readinessState 保存应用生命周期拥有的进程就绪状态。
// 零值为未就绪，HTTP 成功监听后才会切换为就绪。
type readinessState struct {
	ready atomic.Bool
}

func newReadiness() *readinessState { return &readinessState{} }

// MarkReady 标记进程已就绪，仅在 HTTP 监听器绑定成功后调用。
func (r *readinessState) MarkReady() { r.ready.Store(true) }

// MarkNotReady 标记进程未就绪，HTTP 停止与致命运行时失败时调用。
func (r *readinessState) MarkNotReady() { r.ready.Store(false) }

// IsReady 报告进程当前是否就绪。
func (r *readinessState) IsReady() bool { return r.ready.Load() }
