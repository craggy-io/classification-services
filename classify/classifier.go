package classify

import (
	"context"
	"fmt"
	"io"

	"github.com/craggy-io/classification-services/internal/paged"
)

// Spec describes a native classifier to the scheduler.
type Spec struct {
	ID       string
	Produces []string   // types it may assert or reject
	Requires []string   // types that must hold before it runs; empty means "bytes"
	Types    []TypeInfo // types it adds to the catalogue
	Derives  bool       // may emit derived children
	// Revision identifies the implementation. Change it when behaviour
	// changes so cached results for this classifier are recomputed.
	Revision string
}

// Classifier is the native (Go) extension interface.
type Classifier interface {
	Spec() Spec
	Classify(ctx context.Context, in *Input) (Output, error)
}

// ClassifierFunc adapts a function to Classifier.
type ClassifierFunc struct {
	S   Spec
	Run func(ctx context.Context, in *Input) (Output, error)
}

// Spec implements Classifier.
func (f ClassifierFunc) Spec() Spec { return f.S }

// Classify implements Classifier.
func (f ClassifierFunc) Classify(ctx context.Context, in *Input) (Output, error) {
	if f.Run == nil {
		return Output{}, nil
	}
	return f.Run(ctx, in)
}

// Output is everything one classifier run produces.
type Output struct {
	Assertions []Assertion
	Derived    []Derived // honoured only when Spec.Derives is set
	Anomalies  []Anomaly
}

// Assertion is a type assertion or, with Reject, a refutation.
type Assertion struct {
	Type     string
	Level    Level // zero means Recognised (Validated for rejections)
	Metadata map[string]any
	Reject   bool
}

// Assert builds a type assertion.
func Assert(t string, level Level, metadata map[string]any) Assertion {
	return Assertion{Type: t, Level: level, Metadata: metadata}
}

// Refute builds a rejection removing assertions of t below level.
func Refute(t string, level Level) Assertion {
	return Assertion{Type: t, Level: level, Reject: true}
}

// Derived is content derived from the input. Provide Data, a byte range of
// the input (Length > 0), or a random-access Reader with Size.
type Derived struct {
	Name        string
	Data        []byte
	Offset      int64
	Length      int64
	Reader      io.ReaderAt
	Size        int64
	Speculative bool
}

// Input gives a classifier bounded, cached access to the content and to the
// types established so far.
type Input struct {
	r       *paged.Reader
	digest  string
	name    string
	limits  Limits
	matches map[string]Match
}

// Size returns the content size.
func (in *Input) Size() int64 { return in.r.Size() }

// Digest returns the content's SHA-256 (hex).
func (in *Input) Digest() string { return in.digest }

// Name returns the source's file-name hint, or "".
func (in *Input) Name() string { return in.name }

// Limits returns the limits in force.
func (in *Input) Limits() Limits { return in.limits }

// ReadAt implements io.ReaderAt (budgeted, page-cached).
func (in *Input) ReadAt(p []byte, off int64) (int, error) { return in.r.ReadAt(p, off) }

// Read returns up to n bytes at off.
func (in *Input) Read(off, n int64) ([]byte, error) { return in.r.ReadRange(off, n) }

// Prefix returns up to the first n bytes.
func (in *Input) Prefix(n int64) ([]byte, error) { return in.r.ReadRange(0, n) }

// Section returns a reader over a range of the content.
func (in *Input) Section(off, n int64) *io.SectionReader { return io.NewSectionReader(in.r, off, n) }

// Text returns up to limit bytes as a string.
func (in *Input) Text(limit int64) (string, error) {
	b, err := in.Prefix(limit)
	return string(b), err
}

// JSON decodes the content (up to limit bytes) as one JSON value.
func (in *Input) JSON(limit int64) (any, error) { return in.r.JSON(limit) }

// View returns a memoised named view (see package views).
func (in *Input) View(name string) (any, error) { return in.r.View(name) }

// Facet returns the match for t if it is established (directly or by
// inheritance) at the time this classifier was scheduled.
func (in *Input) Facet(t string) (Match, bool) {
	m, ok := in.matches[t]
	return m, ok
}

// Has reports whether t is established.
func (in *Input) Has(t string) bool {
	_, ok := in.matches[t]
	return ok
}

// View fetches a typed view: classify.View[*views.Zip](in, "zip").
func View[T any](in *Input, name string) (T, error) {
	var zero T
	v, err := in.View(name)
	if err != nil {
		return zero, err
	}
	t, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("classify: view %q has type %T", name, v)
	}
	return t, nil
}
