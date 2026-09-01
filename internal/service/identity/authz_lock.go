package identity

import "sync"

// userLockRegistry 按用户串行化进程内操作，零值可直接使用；不同用户使用
// 不同的锁，不会被全局互相阻塞。
type userLockRegistry struct {
	mu      sync.Mutex
	entries map[int64]*userLockEntry
}

type userLockEntry struct {
	mu   sync.Mutex
	refs int
}

// authzLockRegistry 保留授权缓存锁的既有类型名称。
type authzLockRegistry = userLockRegistry

// lock 获取用户级锁并返回释放函数。refs 同时计数持有者与等待者，避免同一
// 用户仍有排队操作时提前删除锁条目。
func (r *userLockRegistry) lock(userID int64) func() {
	r.mu.Lock()
	if r.entries == nil {
		r.entries = make(map[int64]*userLockEntry)
	}
	entry := r.entries[userID]
	if entry == nil {
		entry = &userLockEntry{}
		r.entries[userID] = entry
	}
	entry.refs++
	r.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()

		r.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(r.entries, userID)
		}
		r.mu.Unlock()
	}
}
