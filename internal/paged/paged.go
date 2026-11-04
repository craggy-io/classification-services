// Package paged is the per-input access layer: a page cache over an
// io.ReaderAt with a cumulative read budget, plus memoised views. One Reader
// is shared by every classifier running on the same input, so a ZIP central
// directory is parsed once however many classifiers ask for it.
package paged

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/craggy-io/classification-services/views"
)

// PageSize is the read granularity.
const PageSize = 64 << 10

// ErrBudget is returned once the read budget is exhausted.
var ErrBudget = errors.New("paged: read budget exhausted")

// Reader is safe for concurrent use.
type Reader struct {
	ra     io.ReaderAt
	size   int64
	budget int64

	pulled    atomic.Int64 // bytes read from the underlying reader
	exhausted atomic.Bool

	mu    sync.Mutex
	pages map[int64][]byte

	viewMu sync.Mutex
	views  map[string]*memo
}

type memo struct {
	once sync.Once
	v    any
	err  error
}

// New wraps ra (of the given size) with a total read budget.
func New(ra io.ReaderAt, size, budget int64) *Reader {
	if budget <= 0 {
		budget = 64 << 20
	}
	return &Reader{ra: ra, size: size, budget: budget, pages: map[int64][]byte{}, views: map[string]*memo{}}
}

// Size returns the content size.
func (r *Reader) Size() int64 { return r.size }

// Pulled returns the bytes read from the underlying reader so far.
func (r *Reader) Pulled() int64 { return r.pulled.Load() }

// Exhausted reports whether any read hit the budget.
func (r *Reader) Exhausted() bool { return r.exhausted.Load() }

// ReadAt implements io.ReaderAt through the page cache.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("paged: negative offset %d", off)
	}
	if off >= r.size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		if pos >= r.size {
			return n, io.EOF
		}
		no := pos / PageSize
		page, err := r.page(no)
		if err != nil {
			return n, err
		}
		c := copy(p[n:], page[pos-no*PageSize:])
		if c == 0 {
			return n, io.ErrUnexpectedEOF
		}
		n += c
	}
	return n, nil
}

func (r *Reader) page(no int64) ([]byte, error) {
	r.mu.Lock()
	pg, ok := r.pages[no]
	r.mu.Unlock()
	if ok {
		return pg, nil
	}
	start := no * PageSize
	n := min(int64(PageSize), r.size-start)
	if n <= 0 {
		return nil, io.EOF
	}
	if r.pulled.Add(n) > r.budget+PageSize {
		r.exhausted.Store(true)
		return nil, ErrBudget
	}
	buf := make([]byte, n)
	rd, err := r.ra.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if int64(rd) < n {
		return nil, io.ErrUnexpectedEOF
	}
	r.mu.Lock()
	r.pages[no] = buf
	r.mu.Unlock()
	return buf, nil
}

// ReadRange reads up to n bytes at off, returning fewer at EOF.
func (r *Reader) ReadRange(off, n int64) ([]byte, error) {
	return views.ReadRange(r, r.size, off, n)
}

// View returns the memoised named view (see package views).
func (r *Reader) View(name string) (any, error) {
	parse, ok := views.Lookup(name)
	if !ok {
		return nil, fmt.Errorf("paged: unknown view %q", name)
	}
	return r.memo("view:"+name, func() (any, error) { return parse(r, r.size) })
}

// JSON decodes the content (up to limit bytes) as exactly one JSON value,
// with numbers as json.Number. The decode for the whole content is memoised.
func (r *Reader) JSON(limit int64) (any, error) {
	if limit <= 0 || limit > r.size {
		limit = r.size
	}
	return r.memo(fmt.Sprintf("json:%d", limit), func() (any, error) {
		b, err := r.ReadRange(0, limit)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("paged: trailing data after JSON value")
		}
		return v, nil
	})
}

func (r *Reader) memo(key string, fn func() (any, error)) (any, error) {
	r.viewMu.Lock()
	m, ok := r.views[key]
	if !ok {
		m = &memo{}
		r.views[key] = m
	}
	r.viewMu.Unlock()
	m.once.Do(func() {
		defer func() {
			if p := recover(); p != nil {
				m.err = fmt.Errorf("paged: %s parser panicked: %v", key, p)
			}
		}()
		m.v, m.err = fn()
	})
	return m.v, m.err
}
