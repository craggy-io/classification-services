package classify

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"sort"
	"strings"
	"testing/fstest"
	"time"

	"github.com/craggy-io/foundation-kit/bundle"

	"github.com/craggy-io/classification-services/definitions"
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

// CheckError is returned by Define and DefineModules when any module's
// inline tests fail. Reports holds every module's report, in the order
// given; Passed tells which failed.
type CheckError struct{ Reports []*CheckReport }

func (e *CheckError) Error() string {
	var msgs []string
	for _, r := range e.Reports {
		var failed []string
		for _, t := range r.Tests {
			if !t.Passed {
				failed = append(failed, fmt.Sprintf("%s (%s)", t.Name, strings.Join(t.Failures, "; ")))
			}
		}
		if len(failed) > 0 {
			msgs = append(msgs, fmt.Sprintf("definition %q failed its tests: %s", r.Module, strings.Join(failed, ", ")))
		}
	}
	return "classify: " + strings.Join(msgs, "; ")
}

// ModuleSource is one definition module for CheckModules, PreviewModules or
// DefineModules: its name and Starlark source. The CLI builds these from a
// bundle's classify.module@1 contributions, whose IDs are the names.
type ModuleSource struct {
	Name   string
	Source []byte
}

// validModules checks names and rejects duplicates.
func validModules(mods []ModuleSource) error {
	if len(mods) == 0 {
		return fmt.Errorf("classify: no definition modules given")
	}
	seen := map[string]bool{}
	for _, m := range mods {
		if !definitions.ValidName(m.Name) {
			return fmt.Errorf("classify: invalid definition name %q", m.Name)
		}
		if seen[m.Name] {
			return fmt.Errorf("classify: definition %q given twice", m.Name)
		}
		seen[m.Name] = true
	}
	return nil
}

func spanKey(mods []ModuleSource) string {
	names := make([]string, len(mods))
	for i, m := range mods {
		names[i] = m.Name
	}
	return strings.Join(names, ",")
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

// installedFiles returns the installed bundle as it would be with set
// added or replaced and remove dropped: the modules cur has from the
// installed bundle, each as <name>.star, and a bundle.yaml listing them. It
// returns nil when no module would remain.
func installedFiles(cur *snapshot, set []ModuleSource, remove string) fstest.MapFS {
	mods := map[string][]byte{}
	for n, owner := range cur.owners {
		if owner == InstalledBundle {
			mods[n] = cur.modules[n].Source
		}
	}
	for _, m := range set {
		mods[m.Name] = m.Source
	}
	delete(mods, remove)
	if len(mods) == 0 {
		return nil
	}
	names := slices.Sorted(maps.Keys(mods))
	var m strings.Builder
	m.WriteString("# Written by classify.Engine.Define and Remove. Change it through them.\n")
	m.WriteString("apiVersion: craggy.io/bundle/v1\n\nmetadata:\n")
	fmt.Fprintf(&m, "  id: %s\n  version: 1.0.0\n  title: Definitions installed with Define\n\ncontributions:\n", InstalledBundle)
	files := fstest.MapFS{}
	for _, n := range names {
		fmt.Fprintf(&m, "  - id: %q\n    kind: %s\n    path: %q\n", n, definitions.ModuleKind.ID(), n+".star")
		files[n+".star"] = &fstest.MapFile{Data: mods[n], Mode: 0o644}
	}
	files["bundle.yaml"] = &fstest.MapFile{Data: []byte(m.String()), Mode: 0o644}
	return files
}

// candidate loads the definitions as they would be with installed as the
// installed bundle (nil for none), through the same bundle.Load path as
// the engine, and builds the resulting snapshot. Nothing is written.
func (e *Engine) candidate(ctx context.Context, installed fstest.MapFS) (*snapshot, error) {
	var src bundle.Source
	if installed != nil {
		src = bundle.Embedded(InstalledBundle+" (candidate)", installed)
	}
	cat, err := bundle.Load(ctx, e.options(src))
	if err != nil {
		return nil, err
	}
	return newSnapshot(cat, e.natives)
}

// check builds the snapshot with mods defined, from cur, and returns it
// with each module's report, in order.
func (e *Engine) check(ctx context.Context, cur *snapshot, mods []ModuleSource) (*snapshot, []*CheckReport, error) {
	if err := validModules(mods); err != nil {
		return nil, nil, err
	}
	cand, err := e.candidate(ctx, installedFiles(cur, mods, ""))
	if err != nil {
		return nil, nil, err
	}
	reps := make([]*CheckReport, len(mods))
	selected := map[string]bool{}
	for _, m := range mods {
		selected[m.Name] = true
	}
	for i, m := range mods {
		reps[i] = e.report(ctx, cur, cand, cand.modules[m.Name], selected)
	}
	return cand, reps, nil
}

func passed(reps []*CheckReport) bool {
	for _, r := range reps {
		if !r.Passed() {
			return false
		}
	}
	return true
}

// Check validates a module without installing it: it must compile, every
// type it references must exist, the catalogue must stay acyclic and every
// inline test() must pass against the resulting snapshot.
func (e *Engine) Check(ctx context.Context, name string, source []byte) (*CheckReport, error) {
	reps, err := e.CheckModules(ctx, ModuleSource{Name: name, Source: source})
	if err != nil {
		return nil, err
	}
	return reps[0], nil
}

// CheckModules is Check for several modules at once, validated and tested
// together in one candidate snapshot, so they may use each other's types.
// It returns one report per module, in order.
func (e *Engine) CheckModules(ctx context.Context, mods ...ModuleSource) ([]*CheckReport, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	sp := startSpan(e.cfg.observer, nil, "check", spanKey(mods))
	_, reps, err := e.check(ctx, e.snap.Load(), mods)
	sp.end(err)
	return reps, err
}

// declarers maps each type a snapshot's modules declare to its module.
func declarers(s *snapshot) map[string]string {
	out := map[string]string{}
	for n, m := range s.modules {
		for _, t := range m.Types {
			out[t.Name] = n
		}
	}
	return out
}

// report describes mod in cand against cur. A type change is attributed to
// the selected module that declares the type (now, or before for a removed
// type); a change no selected module declares, such as a descendant whose
// revision follows its parent, is listed in every report.
func (e *Engine) report(ctx context.Context, cur, cand *snapshot, mod *definitions.Module, selected map[string]bool) *CheckReport {
	rep := &CheckReport{Module: mod.Name, Doc: mod.Doc, Revision: cand.revision, Signatures: len(mod.Signatures)}
	_, rep.Replaces = cur.modules[mod.Name]
	before, after := declarers(cur), declarers(cand)
	mine := func(t string) bool {
		owner, ok := after[t]
		if !ok || !selected[owner] {
			owner, ok = before[t]
		}
		return !ok || !selected[owner] || owner == mod.Name
	}
	for _, t := range cand.catalog.Types() {
		old, ok := cur.catalog.Get(t.Name)
		switch {
		case !mine(t.Name):
		case !ok:
			rep.AddedTypes = append(rep.AddedTypes, t.Name)
		case cur.catalog.TypeRevision(t.Name) != cand.catalog.TypeRevision(t.Name):
			rep.ChangedTypes = append(rep.ChangedTypes, old.Name)
		}
	}
	for _, t := range cur.catalog.Types() {
		if !cand.catalog.Has(t.Name) && mine(t.Name) {
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
// adding it as <name>.star to the installed bundle at
// workdir/definitions/classify.installed and rewriting that bundle's
// bundle.yaml. Re-defining a name replaces it; defining a built-in's name
// overrides the built-in until Remove. If any inline test fails nothing is
// installed and the error is a *CheckError carrying the report. Calls in
// flight keep their snapshot.
func (e *Engine) Define(ctx context.Context, name string, source []byte) (*CheckReport, error) {
	reps, err := e.DefineModules(ctx, ModuleSource{Name: name, Source: source})
	if len(reps) == 0 {
		return nil, err
	}
	return reps[0], err
}

// DefineModules is Define for several modules at once. They are checked
// and tested together, and installed in one Live.Install only if every
// module's tests pass; otherwise nothing is installed and the error is a
// *CheckError. It returns one report per module, in order.
func (e *Engine) DefineModules(ctx context.Context, mods ...ModuleSource) ([]*CheckReport, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sp := startSpan(e.cfg.observer, nil, "define", spanKey(mods))
	reps, err := e.define(ctx, mods)
	sp.end(err)
	return reps, err
}

// defineAttempts bounds how often Define starts again because another
// process changed the installed bundle while its tests ran.
const defineAttempts = 3

func (e *Engine) define(ctx context.Context, mods []ModuleSource) ([]*CheckReport, error) {
	if err := validModules(mods); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.refresh(ctx); err != nil {
		return nil, err
	}
	for range defineAttempts {
		cur := e.snap.Load()
		_, reps, err := e.check(ctx, cur, mods)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return reps, err
		}
		if !passed(reps) {
			return reps, &CheckError{Reports: reps}
		}
		// Rebuild on current state if another process installed or removed
		// a definition while the tests ran, so its change is kept.
		if changed, err := e.refresh(ctx); err != nil {
			return reps, err
		} else if changed {
			continue
		}
		if _, err := e.live.Install(ctx, e.store.DefinitionsDir(), installedFiles(cur, mods, "")); err != nil {
			return reps, fmt.Errorf("classify: installing %s: %w", spanKey(mods), err)
		}
		if _, err := e.apply(); err != nil {
			return reps, err
		}
		return reps, nil
	}
	return nil, fmt.Errorf("classify: %s not installed: the installed definitions changed during each of %d attempts", spanKey(mods), defineAttempts)
}

// Remove uninstalls a module installed with Define. Removing a module that
// replaced a built-in restores the built-in. Modules from the built-in
// bundle or a WithSources bundle cannot be removed.
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
	cur := e.snap.Load()
	switch owner, ok := cur.owners[name]; {
	case !ok:
		return fmt.Errorf("classify: definition %q is not installed in the workdir: %w", name, fs.ErrNotExist)
	case owner == BuiltinBundle:
		return fmt.Errorf("classify: definition %q is built in and cannot be removed", name)
	case owner != InstalledBundle:
		return fmt.Errorf("classify: definition %q comes from bundle %s, not the workdir, and cannot be removed", name, owner)
	}
	files := installedFiles(cur, nil, name)
	if _, err := e.candidate(ctx, files); err != nil {
		return fmt.Errorf("classify: removing %q would break the catalogue: %w", name, err)
	}
	var err error
	if files == nil {
		err = e.live.Uninstall(ctx, e.store.DefinitionsDir(), InstalledBundle)
	} else {
		_, err = e.live.Install(ctx, e.store.DefinitionsDir(), files)
	}
	if err != nil {
		return fmt.Errorf("classify: removing definition %q: %w", name, err)
	}
	_, err = e.apply()
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
	Checks   []*CheckReport `json:"checks"` // one per module, in order
	Examined int            `json:"examined"`
	Changes  []Change       `json:"changes,omitempty"`
	Errors   []string       `json:"errors,omitempty"`
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
	return e.PreviewModules(ctx, []ModuleSource{{Name: name, Source: source}}, sources...)
}

// PreviewModules is Preview for several modules installed together.
func (e *Engine) PreviewModules(ctx context.Context, mods []ModuleSource, sources ...Source) (*PreviewReport, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	sp := startSpan(e.cfg.observer, nil, "preview", spanKey(mods))
	cur := e.snap.Load()
	cand, reps, err := e.check(ctx, cur, mods)
	if err != nil {
		sp.end(err)
		return nil, err
	}
	rep := &PreviewReport{Checks: reps}
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
