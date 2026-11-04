package classify

import (
	"sync/atomic"
	"time"
)

// Event reports progress of one operation. Each operation emits a start
// event and exactly one Final event; ParentID links nested operations (a
// classifier run inside a node inside a classify call). Counters are the
// operation's own totals and are never rolled up from children.
//
// Operations: "classify" (one Classify call, keyed by root digest),
// "node" (one content node), "classifier" (one classifier run on a node,
// keyed by classifier ID), "define", "remove", "check", "preview",
// "refresh" and "maintain".
//
// Counters used: "bytes_read", "signature_hits", "classifiers_run",
// "classifiers_cached", "children", "anomalies", "cache_hit" (whole-result
// cache), "nodes".
type Event struct {
	ID       uint64
	ParentID uint64
	Op       string
	Key      string
	Counters map[string]int64
	Elapsed  time.Duration
	Final    bool
	Err      error
}

// Observer receives events synchronously. It must not block for long or
// call back into the engine on the same goroutine.
type Observer func(Event)

var nextEventID atomic.Uint64

type span struct {
	obs   Observer
	ev    Event
	start time.Time
}

func combine(a, b Observer) Observer {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	return func(e Event) { a(e); b(e) }
}

// startSpan begins an operation; a nil observer makes it a no-op.
func startSpan(obs Observer, parent *span, op, key string) *span {
	if obs == nil {
		return nil
	}
	s := &span{obs: obs, start: time.Now(), ev: Event{ID: nextEventID.Add(1), Op: op, Key: key}}
	if parent != nil {
		s.ev.ParentID = parent.ev.ID
	}
	s.obs(s.ev)
	return s
}

func (s *span) count(name string, n int64) {
	if s == nil || n == 0 {
		return
	}
	if s.ev.Counters == nil {
		s.ev.Counters = map[string]int64{}
	}
	s.ev.Counters[name] += n
}

func (s *span) end(err error) {
	if s == nil || s.ev.Final {
		return
	}
	s.ev.Final, s.ev.Err, s.ev.Elapsed = true, err, time.Since(s.start)
	ev := s.ev
	if ev.Counters != nil {
		c := make(map[string]int64, len(ev.Counters))
		for k, v := range ev.Counters {
			c[k] = v
		}
		ev.Counters = c
	}
	s.obs(ev)
}
