package classify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/craggy-io/foundation-kit/bundle"

	"github.com/craggy-io/classification-services/definitions"
)

// CheckReport describes a candidate set of definition modules, checked as one
// change: what it adds or changes, and the outcome of its inline tests.
type CheckReport struct {
	Modules      []string     `json:"modules"`            // sorted
	Revision     string       `json:"revision"`           // snapshot revision if installed
	Replaces     []string     `json:"replaces,omitempty"` // modules that already exist
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

// CheckError is returned by Define when any inline test fails.
type CheckError struct{ Report *CheckReport }

func (e *CheckError) Error() string {
	var failed []string
	for _, t := range e.Report.Tests {
		if !t.Passed {
			failed = append(failed, fmt.Sprintf("%s (%s)", t.Name, strings.Join(t.Failures, "; ")))
		}
	}
	return fmt.Sprintf("classify: definitions %s failed their tests: %s", strings.Join(e.Report.Modules, ", "), strings.Join(failed, ", "))
}

// refresh reloads the definitions catalog, picking up other processes'
// installs, and applies it. It reports whether the snapshot changed.
// Callers hold e.mu.
func (e *Engine) refresh(ctx context.Context) (bool, error) {
	e.lastRefresh.Store(time.Now().UnixNano())
	if _, err := e.live.Reload(ctx); err != nil {
		return false, fmt.Errorf("classify: reloading definitions: %w", err)
	}
	return e.apply()
}

// puts lists modules, by name, as contributions of the installed bundle.
func puts(modules map[string][]byte) []bundle.Put {
	var out []bundle.Put
	for _, n := range slices.Sorted(maps.Keys(modules)) {
		out = append(out, bundle.Put{ID: n, Kind: definitions.ModuleKind.ID(), Path: n + ".star", Data: modules[n]})
	}
	return out
}

// check refreshes, then builds the snapshot Define would install with modules
// added, by making the same Live.Edit on a copy of the installed bundle in a
// temporary folder, and reports on it. Nothing in the workdir changes.
// Callers hold e.mu.
func (e *Engine) check(ctx context.Context, modules map[string][]byte) (cur, cand *snapshot, rep *CheckReport, err error) {
	if _, err := e.refresh(ctx); err != nil {
		return nil, nil, nil, err
	}
	tmp, err := os.MkdirTemp("", "classify-check-")
	if err != nil {
		return nil, nil, nil, err
	}
	defer os.RemoveAll(tmp)
	if err := os.CopyFS(filepath.Join(tmp, InstalledBundle), os.DirFS(e.installedDir())); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, err
	}
	live, err := bundle.NewLive(ctx, func(context.Context) (bundle.Options, error) { return e.options(tmp) })
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := live.Edit(ctx, tmp, InstalledBundle, puts(modules), nil); err != nil {
		return nil, nil, nil, err
	}
	cur = e.snap.Load()
	if cand, err = newSnapshot(live.Catalog(), e.natives); err != nil {
		return nil, nil, nil, err
	}
	return cur, cand, e.report(ctx, cur, cand, slices.Sorted(maps.Keys(modules))), nil
}

// Check validates modules, which maps module names to Starlark source,
// without installing them. They are checked together, so they may use each
// other's types: each must compile, every type they reference must exist,
// the catalogue must stay acyclic and every inline test() must pass against
// the resulting snapshot.
func (e *Engine) Check(ctx context.Context, modules map[string][]byte) (*CheckReport, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	sp := startSpan(e.cfg.observer, nil, "check", spanKey(modules))
	e.mu.Lock()
	_, _, rep, err := e.check(ctx, modules)
	e.mu.Unlock()
	sp.end(err)
	return rep, err
}

func spanKey(modules map[string][]byte) string {
	return strings.Join(slices.Sorted(maps.Keys(modules)), ",")
}

// report describes the modules names in cand against cur.
func (e *Engine) report(ctx context.Context, cur, cand *snapshot, names []string) *CheckReport {
	rep := &CheckReport{Modules: names, Revision: cand.revision}
	for _, t := range cand.catalog.Types() {
		switch {
		case !cur.catalog.Has(t.Name):
			rep.AddedTypes = append(rep.AddedTypes, t.Name)
		case cur.catalog.TypeRevision(t.Name) != cand.catalog.TypeRevision(t.Name):
			rep.ChangedTypes = append(rep.ChangedTypes, t.Name)
		}
	}
	for _, t := range cur.catalog.Types() {
		if !cand.catalog.Has(t.Name) {
			rep.RemovedTypes = append(rep.RemovedTypes, t.Name)
		}
	}
	for _, n := range names {
		if _, ok := cur.modules[n]; ok {
			rep.Replaces = append(rep.Replaces, n)
		}
		mod := cand.modules[n]
		rep.Signatures += len(mod.Signatures)
		for _, c := range mod.Classifiers {
			rep.Classifiers = append(rep.Classifiers, c.ID)
		}
		for _, t := range mod.Tests {
			rep.Tests = append(rep.Tests, e.runTest(ctx, cand, t))
		}
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

// Define validates and tests modules together, as Check does, and only if
// every test passes installs them with Live.Edit, as <name>.star in the
// installed bundle at workdir/definitions/classify.installed. Re-defining a
// name replaces it; defining a built-in's name overrides the built-in until
// Remove. If any inline test fails nothing is installed and the error is a
// *CheckError carrying the report. Calls in flight keep their snapshot.
func (e *Engine) Define(ctx context.Context, modules map[string][]byte) (*CheckReport, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	sp := startSpan(e.cfg.observer, nil, "define", spanKey(modules))
	rep, err := e.define(ctx, modules)
	sp.end(err)
	return rep, err
}

func (e *Engine) define(ctx context.Context, modules map[string][]byte) (*CheckReport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _, rep, err := e.check(ctx, modules)
	if err != nil {
		return nil, err
	}
	if !rep.Passed() {
		return rep, &CheckError{Report: rep}
	}
	if _, err := e.live.Edit(ctx, e.store.DefinitionsDir(), InstalledBundle, puts(modules), nil); err != nil {
		return rep, fmt.Errorf("classify: installing %s: %w", spanKey(modules), err)
	}
	_, err = e.apply()
	return rep, err
}

// Remove uninstalls a module installed with Define. Removing a module that
// replaced a built-in restores the built-in. Modules from the built-in
// bundle or a WithSources bundle cannot be removed.
func (e *Engine) Remove(ctx context.Context, name string) error {
	if e.closed.Load() {
		return ErrClosed
	}
	sp := startSpan(e.cfg.observer, nil, "remove", name)
	err := e.remove(ctx, name)
	sp.end(err)
	return err
}

func (e *Engine) remove(ctx context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.refresh(ctx); err != nil {
		return err
	}
	if d, ok := bundle.Lookup(e.snap.Load().bundles, definitions.ModuleKind, name); ok && d.Owner.ID != InstalledBundle {
		return fmt.Errorf("classify: definition %q comes from bundle %s, not the workdir, and cannot be removed", name, d.Owner.ID)
	}
	if _, err := e.live.Edit(ctx, e.store.DefinitionsDir(), InstalledBundle, nil, []string{name}); err != nil {
		return fmt.Errorf("classify: removing definition %q: %w", name, err)
	}
	_, err := e.apply()
	return err
}

// Refresh reloads the definition bundles, picking up definitions another
// process installed or removed in the workdir. It reports whether the
// snapshot changed.
func (e *Engine) Refresh(ctx context.Context) (bool, error) {
	if e.closed.Load() {
		return false, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	sp := startSpan(e.cfg.observer, nil, "refresh", e.store.Root())
	changed, err := e.refresh(ctx)
	sp.end(err)
	return changed, err
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

// PreviewReport is the impact of candidate modules on known content.
type PreviewReport struct {
	Check    *CheckReport `json:"check"`
	Examined int          `json:"examined"`
	Changes  []Change     `json:"changes,omitempty"`
	Errors   []string     `json:"errors,omitempty"`
}

// PreviewLimit bounds how many known files Preview re-examines when no
// sources are given.
const PreviewLimit = 500

// Preview reports how installing modules would change the classification
// of sources (top-level types and anomalies). With no sources it uses up to
// PreviewLimit files the engine has classified before that are unchanged on
// disk, so an agent can see what definitions would alter before installing
// them. Nothing is installed.
func (e *Engine) Preview(ctx context.Context, modules map[string][]byte, sources ...Source) (*PreviewReport, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	sp := startSpan(e.cfg.observer, nil, "preview", spanKey(modules))
	e.mu.Lock()
	cur, cand, check, err := e.check(ctx, modules)
	e.mu.Unlock()
	if err != nil {
		sp.end(err)
		return nil, err
	}
	rep := &PreviewReport{Check: check}
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
