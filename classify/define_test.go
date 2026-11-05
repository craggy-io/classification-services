package classify_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/craggy-io/foundation-kit/bundle"
	"github.com/craggy-io/foundation-kit/bundle/bundletest"

	"github.com/craggy-io/classification-services/classify"
	"github.com/craggy-io/classification-services/internal/testkit"
)

const widgetDef = `"""Acme widgets: text starting with WIDGET:."""

type("acme", abstract = True)
type("acme.widget", parents = ["acme", "text"], ext = ["wdg"])
signature("acme.widget", at(0, b"WIDGET:"))

def _widget(ctx):
    if ctx.prefix(7) != b"WIDGET:":
        return ctx.reject("acme.widget")
    ctx.anomaly("acme.seen", severity = "info", message = "a widget", size = ctx.size)
    return ctx.match("acme.widget", level = "validated", version = ctx.text()[7:].strip())

classifier("widget", produces = ["acme.widget"], requires = ["text"], run = _widget)

test("widget", data = "WIDGET: 2\n", expect = ["acme.widget", "text"], primary = "acme.widget", anomalies = ["acme.seen"])
test("not a widget", data = "GADGET: 2\n", absent = ["acme.widget"])
`

func TestDefineCheckRemoveAndPersist(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := classify.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	src := classify.Bytes([]byte("WIDGET: 7\n"))
	if r := classifyOK(t, e, src); r.Is("acme.widget") {
		t.Fatal("widget known before Define")
	}
	rep, err := e.Check(ctx, "acme", []byte(widgetDef))
	if err != nil || !rep.Passed() || !slices.Equal(rep.AddedTypes, []string{"acme", "acme.widget"}) || rep.Doc == "" {
		t.Fatalf("check = %+v, %v", rep, err)
	}
	if r := classifyOK(t, e, src); r.Is("acme.widget") {
		t.Fatal("Check installed the definition")
	}
	if _, err := e.Define(ctx, "acme", []byte(widgetDef)); err != nil {
		t.Fatal(err)
	}
	r := classifyOK(t, e, src)
	if r.Primary != "acme.widget" || !r.HasAnomaly("acme.seen") {
		t.Fatalf("after define = %+v", r)
	}
	if m, _ := r.Get("acme.widget"); m.Metadata["version"] != "7" {
		t.Fatalf("metadata = %v", m.Metadata)
	}

	// Persisted: a fresh engine on the same workdir knows the type.
	e2, err := classify.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !classifyOK(t, e2, src).Is("acme.widget") {
		t.Fatal("definition not persisted")
	}
	if err := e.Remove(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if classifyOK(t, e, src).Is("acme.widget") {
		t.Fatal("still a widget after Remove")
	}
	if err := e.Remove(ctx, "java-archives"); err == nil || !strings.Contains(err.Error(), "built in") {
		t.Fatalf("removing a built-in: %v", err)
	}
	if err := e.Remove(ctx, "nope"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removing unknown: %v", err)
	}
}

func TestDefineRejectsFailingTestsAndBadModules(t *testing.T) {
	ctx := context.Background()
	e := open(t)
	bad := strings.Replace(widgetDef, `primary = "acme.widget"`, `primary = "data.json"`, 1)
	rep, err := e.Define(ctx, "acme", []byte(bad))
	var ce *classify.CheckError
	if !errors.As(err, &ce) || rep.Passed() || !strings.Contains(err.Error(), "primary is acme.widget, want data.json") {
		t.Fatalf("failing test: %v", err)
	}
	if slices.Contains(e.Definitions(), "acme") {
		t.Fatal("module installed despite failing tests")
	}
	for name, src := range map[string]string{
		"syntax":         "def (",
		"unknown-parent": `type("acme.x", parents = ["nope"])`,
		"unknown-produce": `
def _r(ctx):
    return None
classifier("r", produces = ["missing.type"], run = _r)`,
		"cycle":      `type("acme.a", parents = ["acme.b"])` + "\n" + `type("acme.b", parents = ["acme.a"])`,
		"namespace":  `type("archive.weird", parents = ["text"])`,
		"dup-id":     "def _r(ctx):\n    return None\nclassifier(\"zip\", run = _r)",
		"bad-sig":    `signature("missing.type", at(0, "00"))`,
		"Bad Name!!": `type("acme.ok")`,
	} {
		if _, err := e.Define(ctx, name, []byte(src)); err == nil {
			t.Fatalf("%s: Define accepted %q", name, src)
		}
	}
}

func TestCacheAcrossEnginesAndOnlyNewClassifierRuns(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	var runs atomic.Int64
	counting := classify.ClassifierFunc{
		S: classify.Spec{ID: "counting", Produces: []string{"probe.counted"}, Types: []classify.TypeInfo{{Name: "probe.counted", Parents: []string{"bytes"}}}, Revision: "1"},
		Run: func(_ context.Context, in *classify.Input) (classify.Output, error) {
			if in.Size() == int64(len("some content")) {
				runs.Add(1) // ignore the inline-test inputs Define classifies
			}
			return classify.Output{Assertions: []classify.Assertion{classify.Assert("probe.counted", classify.Validated, nil)}}, nil
		},
	}
	src := classify.Bytes([]byte("some content"))
	e1, _ := classify.Open(ctx, dir, classify.WithClassifier(counting))
	classifyOK(t, e1, src)
	e2, _ := classify.Open(ctx, dir, classify.WithClassifier(counting))
	r := classifyOK(t, e2, src)
	if runs.Load() != 1 || !r.Is("probe.counted") {
		t.Fatalf("runs = %d (want 1: second engine uses the cache)", runs.Load())
	}
	// A new definition invalidates the whole-result entry but not the
	// per-classifier entries: only the new classifier runs.
	if _, err := e2.Define(ctx, "acme", []byte(widgetDef)); err != nil {
		t.Fatal(err)
	}
	classifyOK(t, e2, src)
	if runs.Load() != 1 {
		t.Fatalf("existing classifier re-ran after Define (runs = %d)", runs.Load())
	}
}

func TestInFlightSnapshotIsStable(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	started := make(chan struct{})
	slow := classify.ClassifierFunc{
		S: classify.Spec{ID: "slow", Produces: []string{"probe.slow"}, Types: []classify.TypeInfo{{Name: "probe.slow", Parents: []string{"bytes"}}}},
		Run: func(context.Context, *classify.Input) (classify.Output, error) {
			close(started)
			<-release
			return classify.Output{Assertions: []classify.Assertion{classify.Assert("probe.slow", classify.Validated, nil)}}, nil
		},
	}
	e := open(t, classify.WithClassifier(slow))
	var r *classify.Result
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r, _ = e.Classify(ctx, classify.Bytes([]byte("WIDGET: 1")))
	}()
	<-started
	if _, err := e.Define(ctx, "acme", []byte(widgetDef)); err != nil {
		t.Fatal(err)
	}
	close(release)
	wg.Wait()
	if r.Is("acme.widget") || !r.Is("probe.slow") {
		t.Fatalf("in-flight call saw the new snapshot: %v", r.Types())
	}
	if !classifyOK(t, e, classify.Bytes([]byte("WIDGET: 1"))).Is("acme.widget") {
		t.Fatal("new call did not see the new snapshot")
	}
}

func TestRefreshAcrossProcesses(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a, _ := classify.Open(ctx, dir)
	b, _ := classify.Open(ctx, dir, classify.WithAutoRefresh(time.Nanosecond))
	c, _ := classify.Open(ctx, dir)
	if _, err := a.Define(ctx, "acme", []byte(widgetDef)); err != nil {
		t.Fatal(err)
	}
	src := classify.Bytes([]byte("WIDGET: 3"))
	if !classifyOK(t, b, src).Is("acme.widget") {
		t.Fatal("auto-refresh engine missed another engine's Define")
	}
	if classifyOK(t, c, src).Is("acme.widget") {
		t.Fatal("engine without auto-refresh reloaded on its own")
	}
	if changed, err := c.Refresh(ctx); err != nil || !changed {
		t.Fatalf("Refresh = %v, %v", changed, err)
	}
	if changed, _ := c.Refresh(ctx); changed {
		t.Fatal("second Refresh reported a change")
	}
	if !classifyOK(t, c, src).Is("acme.widget") {
		t.Fatal("Refresh did not install the definition")
	}
}

func TestPreview(t *testing.T) {
	ctx := context.Background()
	e := open(t)
	dir := t.TempDir()
	widget := filepath.Join(dir, "w.txt")
	other := filepath.Join(dir, "o.txt")
	os.WriteFile(widget, []byte("WIDGET: 9\n"), 0o644)
	os.WriteFile(other, []byte("hello\n"), 0o644)
	for _, p := range []string{widget, other} {
		classifyOK(t, e, classify.File(p))
	}
	rep, err := e.Preview(ctx, "acme", []byte(widgetDef))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Examined != 2 || len(rep.Changes) != 1 {
		t.Fatalf("preview = %+v", rep)
	}
	ch := rep.Changes[0]
	if ch.Name != widget || ch.PrimaryBefore != "text" || ch.PrimaryAfter != "acme.widget" || !slices.Equal(ch.AddedAnomalies, []string{"acme.seen"}) {
		t.Fatalf("change = %+v", ch)
	}
	if slices.Contains(e.Definitions(), "acme") {
		t.Fatal("Preview installed the module")
	}
}

func TestStarlarkContextPrimitives(t *testing.T) {
	ctx := context.Background()
	def := `
type("acme.blob", parents = ["bytes"])

def _blob(ctx):
    if ctx.prefix(4) != b"BLOB":
        return None
    n = ctx.u16le(4)
    at = ctx.find(b"END")
    z = ctx.facet("bytes")
    j = ctx.has("data.json")
    ctx.derive_range("tail", 8, ctx.size - 8)
    return [ctx.match("acme.blob", level = "validated", n = n, end = at, json = j, name = ctx.name)]

classifier("blob", produces = ["acme.blob"], derives = True, run = _blob)
test("blob", hex = "424c4f420500000057494447455420454e44", expect = ["acme.blob"])
`
	e := open(t)
	if _, err := e.Define(ctx, "blob", []byte(def)); err != nil {
		t.Fatal(err)
	}
	r := classifyOK(t, e, classify.Bytes([]byte("BLOB\x05\x00\x00\x00WIDGET: END")).Named("x.bin"))
	m, ok := r.Get("acme.blob")
	if !ok || m.Metadata["n"] != float64(5) || m.Metadata["end"] != float64(16) || m.Metadata["json"] != false || m.Metadata["name"] != "x.bin" {
		t.Fatalf("blob = %+v", m)
	}
	if c := child(r, "tail"); c == nil || c.Primary != "text" || c.Size != 11 {
		t.Fatalf("tail = %+v", r.Children)
	}
}

func TestStarlarkRuntimeLimits(t *testing.T) {
	ctx := context.Background()
	e := open(t, classify.WithLimits(classify.Limits{ScriptSteps: 10_000}))
	def := `
type("acme.spin", parents = ["bytes"])
def _spin(ctx):
    n = 0
    for i in range(1000000):
        n += i
    return ctx.match("acme.spin")
def _bad(ctx):
    ctx.derive("x", b"y")
classifier("spin", produces = ["acme.spin"], run = _spin)
classifier("bad", run = _bad)
`
	if _, err := e.Define(ctx, "spin", []byte(def)); err != nil {
		t.Fatal(err)
	}
	r := classifyOK(t, e, classify.Bytes([]byte("x")))
	lims := strings.Join(r.Limitations, "\n")
	if r.Complete || r.Is("acme.spin") || !strings.Contains(lims, `classifier "spin" failed`) || !strings.Contains(lims, "not declared with derives") {
		t.Fatalf("limits = %q", lims)
	}
	// Failures are not cached: a later run still reports them.
	if r2 := classifyOK(t, e, classify.Bytes([]byte("x"))); r2.Complete {
		t.Fatal("failed run was cached as complete")
	}
}

func widgetBundle(id, module string) fstest.MapFS {
	return fstest.MapFS{
		"bundle.yaml":      {Data: []byte("apiVersion: craggy.io/bundle/v1\nmetadata: {id: " + id + ", version: 1.0.0}\ncontributions:\n  - {id: " + module + ", kind: classify.module@1, path: acme/widget.star}\n")},
		"acme/widget.star": {Data: []byte(widgetDef)},
		"acme/notes.star":  {Data: []byte("def (")}, // not in bundle.yaml, so never loaded
	}
}

func TestWithSources(t *testing.T) {
	src := bundle.Embedded("acme", widgetBundle("acme.defs", "acme"))
	e := open(t, classify.WithSources(src))
	if !classifyOK(t, e, classify.Text("WIDGET: 1")).Is("acme.widget") {
		t.Fatal("WithSources module not loaded")
	}
	e2 := open(t, classify.WithoutBuiltins(), classify.WithSources(src))
	if n := len(e2.Types()); n != 4 { // bytes, text, acme, acme.widget
		t.Fatalf("WithoutBuiltins types = %d", n)
	}
	if err := e.Remove(context.Background(), "acme"); err == nil || !strings.Contains(err.Error(), "acme.defs") {
		t.Fatalf("removing a WithSources module: %v", err)
	}

	// No override applies to WithSources bundles: a built-in's name clashes.
	clash := bundle.Embedded("clash", widgetBundle("acme.clash", "java-archives"))
	_, err := classify.Open(context.Background(), t.TempDir(), classify.WithSources(clash))
	bundletest.RequireCode(t, err, bundle.CodeIDConflict)

	// So does a module installed with Define of a WithSources module's name.
	if _, err := e.Define(context.Background(), "acme", []byte(widgetDef)); err == nil {
		t.Fatal("Define replaced a WithSources module")
	}
}

func TestInstalledBundleOnDisk(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e, err := classify.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Define(ctx, "acme", []byte(widgetDef)); err != nil {
		t.Fatal(err)
	}
	// Replacing a built-in on purpose: the installed bundle overrides it.
	hasJar := func() bool {
		return slices.ContainsFunc(e.Classifiers(), func(s classify.Spec) bool { return s.ID == "jar" })
	}
	if _, err := e.Define(ctx, "java-archives", []byte(`"""No Java classifiers."""`)); err != nil {
		t.Fatal(err)
	}
	if hasJar() {
		t.Fatal("built-in java-archives still active after replacing it")
	}
	inst := filepath.Join(dir, "definitions", classify.InstalledBundle)
	manifest, err := os.ReadFile(filepath.Join(inst, "bundle.yaml"))
	if err != nil || !strings.Contains(string(manifest), `id: "acme"`) || !strings.Contains(string(manifest), `path: "java-archives.star"`) {
		t.Fatalf("installed bundle.yaml = %s, %v", manifest, err)
	}
	if b, err := os.ReadFile(filepath.Join(inst, "acme.star")); err != nil || string(b) != widgetDef {
		t.Fatalf("installed acme.star = %v", err)
	}

	if err := e.Remove(ctx, "java-archives"); err != nil {
		t.Fatal(err)
	}
	if !hasJar() {
		t.Fatal("Remove did not restore the built-in")
	}
	if err := e.Remove(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(inst); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("removing the last module left %s: %v", inst, err)
	}

	// A folder there without a bundle.yaml is an error, never a guess.
	if err := os.MkdirAll(inst, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(inst, "acme.star"), []byte(widgetDef), 0o644)
	if _, err := classify.Open(ctx, dir); err == nil || !strings.Contains(err.Error(), "no bundle.yaml") {
		t.Fatalf("Open with a manifest-less installed folder: %v", err)
	}
}

func TestEngineTestRunsBuiltinModuleTests(t *testing.T) {
	e := open(t)
	res, err := e.Test(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for mod, rs := range res {
		for _, r := range rs {
			n++
			if !r.Passed {
				t.Errorf("%s / %s: %v", mod, r.Name, r.Failures)
			}
		}
	}
	if n < 5 {
		t.Fatalf("only %d built-in tests ran", n)
	}
}

func TestClassifyManyDirAndMaintain(t *testing.T) {
	ctx := context.Background()
	e := open(t)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	files := map[string][]byte{
		"a.json": []byte(`{}`), "sub/b.zip": testkit.Zip(testkit.File{Name: "x", Data: []byte("x")}), "c.bin": {0, 1, 2},
	}
	for n, b := range files {
		os.WriteFile(filepath.Join(dir, n), b, 0o644)
	}
	var mu sync.Mutex
	seen := map[string]string{}
	err := e.ClassifyDir(ctx, dir, func(p string, r *classify.Result, err error) error {
		if err != nil {
			return err
		}
		mu.Lock()
		seen[filepath.ToSlash(strings.TrimPrefix(p, dir+string(filepath.Separator)))] = r.Primary
		mu.Unlock()
		return nil
	})
	if err != nil || seen["a.json"] != "data.json" || seen["sub/b.zip"] != "archive.zip" || seen["c.bin"] != "bytes" {
		t.Fatalf("ClassifyDir = %v, %v", seen, err)
	}
	stop := errors.New("stop")
	if err := e.ClassifyDir(ctx, dir, func(string, *classify.Result, error) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("ClassifyDir stop = %v", err)
	}

	srcs := []classify.Source{classify.Text("{}"), classify.Text("hi")}
	got := make([]string, 2)
	if err := e.ClassifyMany(ctx, srcs, func(i int, r *classify.Result, err error) { got[i] = r.Primary }); err != nil || got[0] != "data.json" || got[1] != "text" {
		t.Fatalf("ClassifyMany = %v, %v", got, err)
	}

	// After replacing a module, Maintain drops entries no snapshot uses.
	if _, err := e.Define(ctx, "acme", []byte(widgetDef)); err != nil {
		t.Fatal(err)
	}
	rep, err := e.Maintain(ctx)
	if err != nil || rep.ResultsRemoved == 0 || rep.ResultsKept == 0 {
		t.Fatalf("Maintain = %+v, %v", rep, err)
	}
	// Results must still be correct afterwards.
	if classifyOK(t, e, classify.File(filepath.Join(dir, "a.json"))).Primary != "data.json" {
		t.Fatal("classification broken after Maintain")
	}
}

func TestDefineModulesInstallsTogetherOrNotAtAll(t *testing.T) {
	ctx := context.Background()
	e := open(t)
	types := classify.ModuleSource{Name: "acme-types", Source: []byte("type(\"acme\", abstract = True)\ntype(\"acme.widget\", parents = [\"acme\", \"text\"])\n")}
	rules := classify.ModuleSource{Name: "acme-rules", Source: []byte(`signature("acme.widget", at(0, b"WIDGET:"))
test("widget", data = "WIDGET: 1", expect = ["acme.widget"])
`)}
	// Alone, the rules module refers to a type it doesn't declare.
	if _, err := e.Check(ctx, rules.Name, rules.Source); err == nil {
		t.Fatal("rules checked without their types")
	}
	failing := classify.ModuleSource{Name: "acme-rules", Source: append(rules.Source, []byte(`test("bad", data = "x", expect = ["acme.widget"])`+"\n")...)}
	reps, err := e.DefineModules(ctx, types, failing)
	var ce *classify.CheckError
	if !errors.As(err, &ce) || len(ce.Reports) != 2 || !ce.Reports[0].Passed() || ce.Reports[1].Passed() {
		t.Fatalf("failing DefineModules = %v", err)
	}
	if slices.Contains(e.Definitions(), "acme-types") {
		t.Fatal("a module was installed although another failed its tests")
	}
	reps, err = e.DefineModules(ctx, types, rules)
	if err != nil || len(reps) != 2 || !slices.Equal(reps[0].AddedTypes, []string{"acme", "acme.widget"}) || len(reps[1].AddedTypes) != 0 {
		t.Fatalf("DefineModules = %+v, %v", reps, err)
	}
	if !classifyOK(t, e, classify.Text("WIDGET: 2")).Is("acme.widget") {
		t.Fatal("modules not installed")
	}
	if _, err := e.DefineModules(ctx, types, types); err == nil {
		t.Fatal("duplicate module accepted")
	}
}
