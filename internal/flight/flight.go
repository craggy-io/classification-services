// Package flight is a minimal typed singleflight: concurrent calls with the
// same key share one execution.
package flight

import "sync"

// Group deduplicates concurrent work by key. The zero value is ready.
type Group[T any] struct {
	mu    sync.Mutex
	calls map[string]*call[T]
}

type call[T any] struct {
	done chan struct{}
	val  T
}

// Do runs fn once per key among concurrent callers. shared reports whether
// this caller received another caller's result.
func (g *Group[T]) Do(key string, fn func() T) (v T, shared bool) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = map[string]*call[T]{}
	}
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		<-c.done
		return c.val, true
	}
	c := &call[T]{done: make(chan struct{})}
	g.calls[key] = c
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.calls, key)
		g.mu.Unlock()
		close(c.done)
	}()
	c.val = fn()
	return c.val, false
}
