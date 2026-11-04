package classify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/craggy-io/classification-services/definitions"
	"github.com/craggy-io/classification-services/internal/cache"
)

// CheckReport describes a candidate definition module: what it adds or
// changes, and the outcome of its inline tests.
type CheckReport struct {
	Module       string       `json:"module"`
	Doc          string       `json:"doc,omitempty"`
	Revision     string       `json:"revision"` // snapshot revision if installed
	Replaces     bool         `json:"replaces"` // a module with this name exists
	AddedTypes   []string     `json:"added_types,omitempty"`
	ChangedTypes []string     `json:"changed_types,omitempty"`
	RemovedTypes []string     `json:"removed_types,omitempty"`
	Classifiers  []string     `json:"classifiers,omitempty"`
	Signatures   int          `json:"signatures"`
	Tests        []TestResult `json:"tests,omitempty"`
}

// Passed reports whether every inline test passed.
func (r *CheckReport) Passed() bool {
	for _, t := range r.Tests {
		if !t.Passed {
			return false
		}
	}
	return true
}

// TestResult is the outcome of one inline test().
type TestResult struct {
	Name      string   `json:"name"`
	Passed    bool     `json:"passed"`
	Failures  []string `json:"failures,omitempty"`
	Primary   string   `json:"primary"`
	Types     []string `json:"types,omitempty"`
	Anomalies []string `json:"anomalies,omitempty"`
}

// CheckError is returned by Define when the module's inline tests fail.
type CheckError struct{ Report *CheckReport }

func (e *CheckError) Error() string {
	var failed []string
	for _, t := range e.Report.Tests {
		if !t.Passed {
			failed = append(failed, fmt.Sprintf("%s (%s)", t.Name, strings.Join(t.Failures, "; ")))
		}
	}
	return fmt.Sprintf("classify: definition %q failed its tests: %s", e.Report.Module, strings.Join(failed, ", "))
}

// syncPersisted reloads the snapshot when another process changed the
// persisted definitions since they were last loaded, so Define/Remove
// build candidates on current state. Callers hold e.mu.
func (e *Engine) syncPersisted() error {
	_, fp, err := e.loadPersisted()
	if err != nil {
		return err
	}
	if fp != e.persisted {
		return e.reload()
	}
	return nil
}

// candidate builds the snapshot that would result from installing (or,
// with a nil module, removing) name. Callers hold e.mu.
func (e *Engine) candidate(name string, mod *definitions.Module) (*snapshot, error) {
	cur := e.snap.Load()
	effective := make(map[string]*definitions.Module, len(cur.modules)+1)
	for n, m := range cur.modules {
		effective[n] = m
	}
	switch {
	case mod != nil:
		effective[name] = mod
	case e.base[name] != nil:
		effective[name] = e.base[name]
	default:
		delete(effective, name)
	}
	return buildSnapshot(effective, e.natives, e.sigs)
}

// Check validates a module without installing it: it must compile, every
// type it references must exist, the catalogue must stay acyclic and every
// inline test() must pass against the resulting snapshot.
func (e *Engine) Check(ctx context.Context, name string, source []byte) (*CheckReport, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	sp := startSpan(e.cfg.observer, nil, "check", name)
	mod, err := definitions.LoadContext(ctx, name, source, e.store)
	if err != nil {
		sp.end(err)
		return nil, err
	}
	e.mu.Lock()
	cand, err := e.candidate(name, mod)
	cur := e.snap.Load()
	e.mu.Unlock()
	if err != nil {
		sp.end(err)
		return nil, err
	}
	rep := e.report(ctx, cur, cand, mod)
	sp.end(nil)
	return rep, nil
}

func (e *Engine) report(ctx context.Context, cur, cand *snapshot, mod *definitions.Module) *CheckReport {
	rep := &CheckReport{Module: mod.Name, Doc: mod.Doc, Revision: cand.revision, Signatures: len(mod.Signatures)}
	_, rep.Replaces = cur.modules[mod.Name]
	for _, t := range cand.catalog.Types() {
		old, ok := cur.catalog.Get(t.Name)
		switch {
		case !ok:
			rep.AddedTypes = append(rep.AddedTypes, t.Name)
		case cur.catalog.TypeRevision(t.Name) != cand.catalog.TypeRevision(t.Name):
			rep.ChangedTypes = append(rep.ChangedTypes, old.Name)
		}
	}
	for _, t := range cur.catalog.Types() {
		if !cand.catalog.Has(t.Name) {
			rep.RemovedTypes = append(rep.RemovedTypes, t.Name)
		}
	}
	for _, c := range mod.Classifiers {
		rep.Classifiers = append(rep.Classifiers, c.ID)
	}
	for _, t := range mod.Tests {
		rep.Tests = append(rep.Tests, e.runTest(ctx, cand, t))
	}
	return rep
}

func (e *Engine) runTest(ctx context.Context, snap *snapshot, t definitions.Test) TestResult {
	tr := TestResult{Name: t.Name}
	src := Bytes(t.Data)
	if t.Text {
		src = Text(string(t.Data))
	}
	if t.FileName != "" {
		src = src.Named(t.FileName)
	}
	r, err := e.classifyWith(ctx, snap, src, WithDepth(Deep))
	if err != nil {
		tr.Failures = append(tr.Failures, err.Error())
		return tr
	}
	tr.Primary, tr.Types = r.Primary, r.Types()
	for _, a := range r.Anomalies {
		tr.Anomalies = append(tr.Anomalies, a.Code)
	}
	for _, want := range t.Expect {
		if !snap.catalog.Has(want) {
			tr.Failures = append(tr.Failures, fmt.Sprintf("unknown type %s in expect", want))
		} else if !r.Is(want) {
			tr.Failures = append(tr.Failures, fmt.Sprintf("expected %s", want))
		}
	}
	for _, no := range t.Absent {
		if !snap.catalog.Has(no) {
			tr.Failures = append(tr.Failures, fmt.Sprintf("unknown type %s in absent", no))
		} else if r.Is(no) {
			tr.Failures = append(tr.Failures, fmt.Sprintf("did not expect %s", no))
		}
	}
	if t.Primary != "" && !snap.catalog.Has(t.Primary) {
		tr.Failures = append(tr.Failures, fmt.Sprintf("unknown type %s in primary", t.Primary))
	} else if t.Primary != "" && r.Primary != t.Primary {
		tr.Failures = append(tr.Failures, fmt.Sprintf("primary is %s, want %s", r.Primary, t.Primary))
	}
	for _, code := range t.Anomalies {
		if !slices.Contains(tr.Anomalies, code) {
			tr.Failures = append(tr.Failures, fmt.Sprintf("expected anomaly %s", code))
		}
	}
	tr.Passed = len(tr.Failures) == 0
	return tr
}

// Define validates, tests and atomically installs a definition module,
// persisting it as workdir/definitions/<name>.star. Re-defining a name
// replaces it; defining a built-in's name shadows the built-in until
// Remove. If any inline test fails nothing is installed and the error is a
// *CheckError carrying the report. Calls in flight keep their snapshot.
func (e *Engine) Define(ctx context.Context, name string, source []byte) (*CheckReport, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sp := startSpan(e.cfg.observer, nil, "define", name)
	mod, err := definitions.LoadContext(ctx, name, source, e.store)
	if err != nil {
		sp.end(err)
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.syncPersisted(); err != nil {
		sp.end(err)
		return nil, err
	}
	cur := e.snap.Load()
	cand, err := e.candidate(name, mod)
	if err != nil {
		sp.end(err)
		return nil, err
	}
	rep := e.report(ctx, cur, cand, mod)
	if err := ctx.Err(); err != nil {
		sp.end(err)
		return rep, err
	}
	if !rep.Passed() {
		err := &CheckError{Report: rep}
		sp.end(err)
		return rep, err
	}
	if err := cache.ReplaceFile(filepath.Join(e.store.DefinitionsDir(), name+".star"), source); err != nil {
		sp.end(err)
		return rep, fmt.Errorf("classify: persisting definition %q: %w", name, err)
	}
	// Reload from disk rather than installing the candidate: definitions
	// another process installed in the meantime must be picked up too.
	if err := e.reload(); err != nil {
		sp.end(err)
		return rep, err
	}
	sp.end(nil)
	return rep, nil
}

// Remove uninstalls a runtime-defined module. Removing a module that
// shadowed a built-in restores the built-in. Built-ins themselves cannot be
// removed.
func (e *Engine) Remove(ctx context.Context, name string) error {
	if e.closed.Load() {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !definitions.ValidName(name) {
		return fmt.Errorf("classify: invalid definition name %q", name)
	}
	sp := startSpan(e.cfg.observer, nil, "remove", name)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.syncPersisted(); err != nil {
		sp.end(err)
		return err
	}
	path := filepath.Join(e.store.DefinitionsDir(), name+".star")
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		err := fmt.Errorf("classify: definition %q is not installed in the workdir: %w", name, fs.ErrNotExist)
		if e.base[name] != nil {
			err = fmt.Errorf("classify: definition %q is built in and cannot be removed", name)
		}
		sp.end(err)
		return err
	}
	cand, err := e.candidate(name, nil)
	if err != nil {
		err = fmt.Errorf("classify: removing %q would break the catalogue: %w", name, err)
		sp.end(err)
		return err
	}
	if err := os.Remove(path); err != nil {
		sp.end(err)
		return err
	}
	// As in Define, reload from disk so other processes' changes survive.
	_ = cand
	if err := e.reload(); err != nil {
		sp.end(err)
		return err
	}
	sp.end(nil)
	return nil
}

// Refresh reloads persisted definitions if another process changed them.
// It reports whether the snapshot changed.
func (e *Engine) Refresh(ctx context.Context) (bool, error) {
	if e.closed.Load() {
		return false, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastRefresh.Store(time.Now().UnixNano())
	_, fp, err := e.loadPersisted()
	if err != nil {
		return false, err
	}
	if fp == e.persisted {
		return false, nil
	}
	sp := startSpan(e.cfg.observer, nil, "refresh", e.store.Root())
	err = e.reload()
	sp.end(err)
	return err == nil, err
}

// Change is one classification that a candidate module would alter.
type Change struct {
	Name             string   `json:"name"`
	Digest           string   `json:"digest"`
	PrimaryBefore    string   `json:"primary_before"`
	PrimaryAfter     string   `json:"primary_after"`
	AddedTypes       []string `json:"added_types,omitempty"`
	RemovedTypes     []string `json:"removed_types,omitempty"`
	AddedAnomalies   []string `json:"added_anomalies,omitempty"`
	RemovedAnomalies []string `json:"removed_anomalies,omitempty"`
}

// PreviewReport is the impact of a candidate module on known content.
type PreviewReport struct {
	Check    *CheckReport `json:"check"`
	Examined int          `json:"examined"`
	Changes  []Change     `json:"changes,omitempty"`
	Errors   []string     `json:"errors,omitempty"`
}

// PreviewLimit bounds how many known files Preview re-examines when no
// sources are given.
const PreviewLimit = 500

// Preview reports how installing the module would change the classification
// of sources (top-level types and anomalies). With no sources it uses up to
// PreviewLimit files the engine has classified before that are unchanged on
// disk, so an agent can see what a definition would alter before installing
// it. Nothing is installed.
func (e *Engine) Preview(ctx context.Context, name string, source []byte, sources ...Source) (*PreviewReport, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	sp := startSpan(e.cfg.observer, nil, "preview", name)
	mod, err := definitions.LoadContext(ctx, name, source, e.store)
	if err != nil {
		sp.end(err)
		return nil, err
	}
	e.mu.Lock()
	cur := e.snap.Load()
	cand, err := e.candidate(name, mod)
	e.mu.Unlock()
	if err != nil {
		sp.end(err)
		return nil, err
	}
	rep := &PreviewReport{Check: e.report(ctx, cur, cand, mod)}
	if len(sources) == 0 {
		for _, k := range e.store.KnownFiles(PreviewLimit) {
			sources = append(sources, File(k.Path))
		}
	}
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			break
		}
		before, err := e.classifyWith(ctx, cur, src)
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			continue
		}
		after, err := e.classifyWith(ctx, cand, src)
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			continue
		}
		rep.Examined++
		if ch, changed := diff(before, after); changed {
			ch.Name = src.path
			if ch.Name == "" {
				ch.Name = src.name
			}
			rep.Changes = append(rep.Changes, ch)
		}
	}
	sort.Slice(rep.Changes, func(i, j int) bool { return rep.Changes[i].Name < rep.Changes[j].Name })
	sp.count("examined", int64(rep.Examined))
	sp.end(nil)
	return rep, nil
}

func diff(a, b *Result) (Change, bool) {
	ch := Change{Digest: a.Digest, PrimaryBefore: a.Primary, PrimaryAfter: b.Primary}
	ch.AddedTypes, ch.RemovedTypes = setDiff(b.Types(), a.Types()), setDiff(a.Types(), b.Types())
	codes := func(r *Result) []string {
		var out []string
		for _, an := range r.Anomalies {
			out = append(out, an.Code)
		}
		return out
	}
	ch.AddedAnomalies, ch.RemovedAnomalies = setDiff(codes(b), codes(a)), setDiff(codes(a), codes(b))
	changed := a.Primary != b.Primary || len(ch.AddedTypes)+len(ch.RemovedTypes)+len(ch.AddedAnomalies)+len(ch.RemovedAnomalies) > 0
	return ch, changed
}

// setDiff returns the sorted elements of a not in b.
func setDiff(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return sortedUnique(out)
}

// Test runs the inline tests of every installed module (built-in and
// runtime-defined) against the active snapshot, keyed by module name.
func (e *Engine) Test(ctx context.Context) (map[string][]TestResult, error) {
	snap, err := e.current()
	if err != nil {
		return nil, err
	}
	out := map[string][]TestResult{}
	for name, tests := range snap.tests {
		for _, t := range tests {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			out[name] = append(out[name], e.runTest(ctx, snap, t))
		}
	}
	return out, nil
}
