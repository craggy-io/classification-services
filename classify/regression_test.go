package classify_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/craggy-io/classification-services/classify"
)

// An incomplete (failed) result must not be served from the whole-result
// LRU on the next Classify of the same content.
func TestIncompleteResultNotLRUCached(t *testing.T) {
	var calls atomic.Int64
	flaky := classify.ClassifierFunc{
		S: classify.Spec{ID: "flaky", Produces: []string{"probe.flaky"}, Types: []classify.TypeInfo{{Name: "probe.flaky", Parents: []string{"bytes"}}}, Revision: "1"},
		Run: func(_ context.Context, _ *classify.Input) (classify.Output, error) {
			if calls.Add(1) == 1 {
				return classify.Output{}, errors.New("boom")
			}
			return classify.Output{Assertions: []classify.Assertion{classify.Assert("probe.flaky", classify.Validated, nil)}}, nil
		},
	}
	e := open(t, classify.WithClassifier(flaky))
	src := classify.Bytes([]byte("content"))
	r1 := classifyOK(t, e, src)
	if r1.Complete {
		t.Fatal("first result should be incomplete")
	}
	r2 := classifyOK(t, e, src)
	if !r2.Complete || !r2.Is("probe.flaky") || calls.Load() < 2 {
		t.Fatalf("second classify served the incomplete cached result: complete=%v calls=%d", r2.Complete, calls.Load())
	}
}

// A classifier that reads the name hint must not get the unnamed run's
// cached outcome for a named source (or vice versa).
func TestNameVisibleClassifierNotCachedAcrossNames(t *testing.T) {
	byName := classify.ClassifierFunc{
		S: classify.Spec{ID: "byname", Produces: []string{"probe.byname"}, Types: []classify.TypeInfo{{Name: "probe.byname", Parents: []string{"bytes"}}}, Revision: "1"},
		Run: func(_ context.Context, in *classify.Input) (classify.Output, error) {
			return classify.Output{Assertions: []classify.Assertion{
				classify.Assert("probe.byname", classify.Validated, map[string]any{"name": in.Name()}),
			}}, nil
		},
	}
	e := open(t, classify.WithClassifier(byName))
	data := []byte("same bytes")
	r1 := classifyOK(t, e, classify.Bytes(data))
	r2 := classifyOK(t, e, classify.Bytes(data).Named("y.bin"))
	m1, _ := r1.Get("probe.byname")
	m2, _ := r2.Get("probe.byname")
	if m1.Metadata["name"] != "" || m2.Metadata["name"] != "y.bin" {
		t.Fatalf("metadata names = %q, %q", m1.Metadata["name"], m2.Metadata["name"])
	}
}

// A Starlark classifier building cyclic metadata must fail its run, not
// crash the process.
func TestCyclicMetadataDoesNotCrash(t *testing.T) {
	e := open(t)
	const mod = `
type("acme", abstract = True)
type("acme.cyc", parents = ["acme"])
def _c(ctx):
    x = []
    x.append(x)
    return ctx.match("acme.cyc", m = x)
classifier("cyc", produces = ["acme.cyc"], run = _c)
test("cyc", data = "x", expect = ["acme.cyc"])
`
	if _, err := e.Define(context.Background(), map[string][]byte{"cyc": []byte(mod)}); err == nil {
		t.Fatal("cyclic-metadata module installed; want its test to fail")
	}
}

// Define with a cancelled context must not persist anything.
func TestDefineCancelledContext(t *testing.T) {
	e := open(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	const mod = `type("acme", abstract = True)
type("acme.x", parents = ["acme"])
`
	if _, err := e.Define(ctx, map[string][]byte{"cancelled": []byte(mod)}); err == nil {
		t.Fatal("Define with cancelled context succeeded")
	}
	for _, d := range e.Definitions() {
		if strings.Contains(d, "cancelled") {
			t.Fatal("cancelled module was installed")
		}
	}
}
