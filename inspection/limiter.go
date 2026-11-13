package inspection

import (
	"context"
	"sync"
	"sync/atomic"
)

// Limiter enforces a hard maximum number of active inspection sessions.
type Limiter struct {
	mu     sync.Mutex
	limit  int64
	active int64
	reject atomic.Uint64
}

func NewLimiter(limit int) *Limiter {
	if limit < 1 {
		limit = 1
	}
	if limit > 512 {
		limit = 512
	}
	return &Limiter{limit: int64(limit)}
}

func (l *Limiter) SetLimit(limit int) bool {
	if limit < 1 {
		limit = 1
	}
	if limit > 512 {
		limit = 512
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active > int64(limit) {
		return false
	}
	l.limit = int64(limit)
	return true
}

// Acquire reserves a session. The release function must be called exactly once.
func (l *Limiter) Acquire(ctx context.Context) (release func(), ok bool) {
	if ctx.Err() != nil {
		return func() {}, false
	}
	l.mu.Lock()
	if l.active >= l.limit {
		l.mu.Unlock()
		l.reject.Add(1)
		return func() {}, false
	}
	l.active++
	l.mu.Unlock()
	var done atomic.Bool
	return func() {
		if done.CompareAndSwap(false, true) {
			l.mu.Lock()
			l.active--
			l.mu.Unlock()
		}
	}, true
}

func (l *Limiter) Active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return int(l.active)
}
func (l *Limiter) Rejected() uint64 { return l.reject.Load() }
func (l *Limiter) Limit() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return int(l.limit)
}
