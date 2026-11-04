package classify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/craggy-io/classification-services/classify"
	"github.com/craggy-io/classification-services/internal/testkit"
)

func open(t testing.TB, opts ...classify.Option) *classify.Engine {
	t.Helper()
	e, err := classify.Open(context.Background(), t.TempDir(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func classifyOK(t testing.TB, e *classify.Engine, src classify.Source, opts ...classify.ClassifyOption) *classify.Result {
	t.Helper()
	r, err := e.Classify(context.Background(), src, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func child(r *classify.Result, name string) *classify.Result {
	for _, c := range r.Children {
		if c.Name == name {
			return c.Result
		}
	}
	return nil
}

func TestBytesRootAndEmpty(t *testing.T) {
	e := open(t)
	r := classifyOK(t, e, classify.Bytes([]byte{0x00, 0xff, 0x13}))
	if r.Primary != "bytes" || !r.IsAtLeast("bytes", classify.Validated) || !r.Complete {
		t.Fatalf("result = %+v", r)
	}
	r = classifyOK(t, e, classify.Bytes(nil))
	if r.Primary != "bytes" || r.Size != 0 {
		t.Fatalf("empty = %+v", r)
	}
}

func TestTextAndJSON(t *testing.T) {
	e := open(t)
	r := classifyOK(t, e, classify.Text(`{"a": [1, 2]}`))
	if r.Primary != "data.json" || !r.Is("text") || !r.Is("data") {
		t.Fatalf("types = %v", r.Types())
	}
	m, _ := r.Get("data.json")
	if m.Metadata["kind"] != "object" || !m.Direct {
		t.Fatalf("json match = %+v", m)
	}
	r = classifyOK(t, e, classify.Bytes([]byte("just some words\n")))
	if r.Primary != "text" {
		t.Fatalf("plain text primary = %s", r.Primary)
	}
}

func TestZipJarAPK(t *testing.T) {
	e := open(t)
	jar := testkit.Zip(testkit.File{Name: "META-INF/MANIFEST.MF", Data: []byte("Main-Class: a.B\n")}, testkit.File{Name: "a/B.class", Data: []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0, 5}})
	r := classifyOK(t, e, classify.Bytes(jar))
	if r.Primary != "archive.jar" || !r.Is("archive.zip") || !r.Is("archive") {
		t.Fatalf("jar types = %v", r.Types())
	}
	if m, _ := r.Get("archive.jar"); m.Metadata["main_class"] != "a.B" {
		t.Fatalf("jar metadata = %v", m.Metadata)
	}
	if c := child(r, "a/B.class"); c == nil || c.Primary != "executable.java-class" {
		t.Fatalf("class child = %+v", c)
	}

	apk := testkit.WithSigningBlock(testkit.Zip(
		testkit.File{Name: "AndroidManifest.xml", Data: testkit.AXML("com.example", false, "android.permission.INTERNET")},
		testkit.File{Name: "classes.dex", Data: dex()},
		testkit.File{Name: "resources.arsc", Data: []byte("arsc")},
	), 0x7109871a)
	r = classifyOK(t, e, classify.Bytes(apk))
	if r.Primary != "android.apk" || !r.IsAtLeast("android.apk", classify.Validated) || !r.Is("android") || !r.Is("archive.zip") {
		t.Fatalf("apk types = %v", r.Types())
	}
	m, _ := r.Get("android.apk")
	if m.Metadata["package"] != "com.example" || !slices.Equal(anyStrings(m.Metadata["signature_schemes"]), []string{"v2"}) {
		t.Fatalf("apk metadata = %v", m.Metadata)
	}
	if c := child(r, "classes.dex"); c == nil || c.Primary != "android.dex" {
		t.Fatalf("dex child = %+v", c)
	}
	if c := child(r, "AndroidManifest.xml"); c == nil || c.Primary != "android.axml" {
		t.Fatalf("manifest child = %+v", c)
	}
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func dex() []byte {
	b := make([]byte, 112)
	copy(b, "dex\n035\x00")
	b[32] = 112
	b[36] = 112
	copy(b[40:], []byte{0x78, 0x56, 0x34, 0x12})
	return b
}

func TestQuickDepthSignaturesOnly(t *testing.T) {
	e := open(t)
	r := classifyOK(t, e, classify.Bytes(testkit.Zip(testkit.File{Name: "a", Data: []byte("a")})), classify.WithDepth(classify.Quick))
	m, ok := r.Get("archive.zip")
	if !ok || m.Level != classify.Candidate || len(r.Children) != 0 {
		t.Fatalf("quick = %+v", r)
	}
	if m.Evidence[0].Kind != "signature" || m.Evidence[0].Offset != 0 {
		t.Fatalf("evidence = %+v", m.Evidence)
	}
}

func TestRejectRefutesCandidate(t *testing.T) {
	e := open(t)
	r := classifyOK(t, e, classify.Bytes([]byte("PK\x03\x04 this is not really a zip archive at all")))
	if r.Is("archive.zip") {
		t.Fatalf("broken zip still a zip: %v", r.Types())
	}
	ex, ok := r.Explain("archive.zip")
	if !ok || ex.Holds || len(ex.Rejections) == 0 || !ex.Rejections[0].Removed || ex.Rejections[0].By != "zip" {
		t.Fatalf("explain = %+v", ex)
	}
}

func TestExplain(t *testing.T) {
	e := open(t)
	r := classifyOK(t, e, classify.Bytes(testkit.Zip(testkit.File{Name: "a", Data: []byte("a")})))
	ex, ok := r.Explain("archive.zip")
	if !ok || !ex.Holds || !ex.Direct || !ex.Primary || ex.Level != classify.Validated {
		t.Fatalf("explain = %+v", ex)
	}
	kinds := map[string]bool{}
	for _, ev := range ex.Evidence {
		kinds[ev.Kind] = true
	}
	if !kinds["signature"] || !kinds["classifier"] {
		t.Fatalf("evidence kinds = %v", kinds)
	}
	in, _ := r.Explain("archive")
	if in.Direct || !slices.Equal(in.Via, []string{"archive.zip"}) || len(in.Evidence) == 0 {
		t.Fatalf("inherited explain = %+v", in)
	}
	if s := ex.String(); !strings.Contains(s, "archive.zip holds (validated, direct), primary") {
		t.Fatalf("rendered = %q", s)
	}
	if _, ok := r.Explain("image.png"); ok {
		t.Fatal("explained a type that neither holds nor was rejected")
	}
}

func TestDerivationGzipTarAndSharedNodes(t *testing.T) {
	e := open(t)
	inner := []byte(`{"same": true}`)
	tgz := testkit.Gzip(testkit.Tar(testkit.File{Name: "a.json", Data: inner}, testkit.File{Name: "b.json", Data: inner}), "x.tar")
	r := classifyOK(t, e, classify.Bytes(tgz))
	if r.Primary != "compression.gzip" {
		t.Fatalf("primary = %s", r.Primary)
	}
	tarNode := child(r, "x.tar")
	if tarNode == nil || tarNode.Primary != "archive.tar" {
		t.Fatalf("tar child = %+v", tarNode)
	}
	a, b := child(tarNode, "a.json"), child(tarNode, "b.json")
	if a == nil || a != b || a.Primary != "data.json" {
		t.Fatalf("identical children are not one shared node: %p %p", a, b)
	}
	var paths [][]string
	r.Walk(func(p []string, _ *classify.Result) error { paths = append(paths, p); return nil })
	if len(paths) != 3 {
		t.Fatalf("walk visited %v", paths)
	}
}

func TestSpeculativeOnlyAtDeep(t *testing.T) {
	e := open(t)
	b64 := "eyJoZWxsbyI6ICJ3b3JsZCIsICJuIjogNDJ9" // {"hello": "world", "n": 42}
	r := classifyOK(t, e, classify.Text(b64))
	if !r.Is("encoding.base64") || len(r.Children) != 0 {
		t.Fatalf("standard = %+v", r)
	}
	r = classifyOK(t, e, classify.Text(b64), classify.WithDepth(classify.Deep))
	c := child(r, "base64")
	if c == nil || c.Primary != "data.json" || !r.Children[0].Speculative {
		t.Fatalf("deep = %+v", r.Children)
	}
	r = classifyOK(t, e, classify.Text("zz9/zz9/zz9/zz9/zz9/zz9/zz9/"), classify.WithDepth(classify.Deep))
	if len(r.Children) != 0 {
		t.Fatalf("speculative noise kept: %+v", r.Children)
	}
}

func TestSources(t *testing.T) {
	e := open(t)
	path := filepath.Join(t.TempDir(), "doc.json")
	os.WriteFile(path, []byte(`[1]`), 0o644)
	r := classifyOK(t, e, classify.File(path))
	if r.Primary != "data.json" || r.Name != "doc.json" {
		t.Fatalf("file = %+v", r)
	}
	r2 := classifyOK(t, e, classify.ReaderAt(bytes.NewReader([]byte(`[1]`)), 3))
	if r2.Digest != r.Digest || r2.Primary != r.Primary {
		t.Fatalf("reader = %+v", r2)
	}
	if _, err := e.Classify(context.Background(), classify.Source{}); !errors.Is(err, classify.ErrInvalidSource) {
		t.Fatalf("zero source err = %v", err)
	}
	if _, err := e.Classify(context.Background(), classify.File(t.TempDir())); !errors.Is(err, classify.ErrInvalidSource) {
		t.Fatalf("directory err = %v", err)
	}
}

func TestAnomalies(t *testing.T) {
	e := open(t)
	poly := append(testkit.ELF(256), testkit.Zip(testkit.File{Name: "payload.sh", Data: []byte("#!/bin/sh\nid\n")})...)
	r := classifyOK(t, e, classify.Bytes(poly).Named("innocent.elf"))
	for _, code := range []string{"polyglot", "zip.prepended-data", "executable.overlay"} {
		if !r.HasAnomaly(code) {
			t.Fatalf("missing %s in %+v", code, r.Anomalies)
		}
	}
	if sev, ok := r.MaxSeverity(); !ok || sev != classify.Warning {
		t.Fatalf("max severity = %v %v", sev, ok)
	}
	if c := child(r, "payload.sh"); c == nil || c.Primary != "source.shell" {
		t.Fatalf("payload not classified: %+v", r.Children)
	}

	r = classifyOK(t, e, classify.Bytes(testkit.PE(false, false)).Named("invoice.pdf"))
	if !r.HasAnomaly("extension-mismatch") || r.Anomalies[0].Severity != classify.Critical {
		t.Fatalf("PE named .pdf: %+v", r.Anomalies)
	}
	r = classifyOK(t, e, classify.Bytes(testkit.PE(false, false)).Named("tool.exe"))
	if r.HasAnomaly("extension-mismatch") {
		t.Fatalf("PE named .exe flagged: %+v", r.Anomalies)
	}
	r = classifyOK(t, e, classify.Bytes(testkit.ELF(128)).Named("setup.exe"))
	if !r.HasAnomaly("extension-mismatch") {
		t.Fatalf("ELF named .exe not flagged (same namespace must not vouch): %+v", r.Anomalies)
	}
	// The cached root is shared; the name-dependent anomaly must not leak.
	r = classifyOK(t, e, classify.Bytes(testkit.PE(false, false)))
	if r.HasAnomaly("extension-mismatch") || r.Name != "" {
		t.Fatalf("anomaly leaked into the cached result: %+v", r)
	}
	r = classifyOK(t, e, classify.Bytes(testkit.Zip(testkit.File{Name: "../../x", Data: []byte("x")})).Named("a.jar"))
	if !r.HasAnomaly("zip.path-traversal") || r.Anomalies[0].Severity != classify.Critical || r.HasAnomaly("extension-mismatch") {
		t.Fatalf("traversal: %+v", r.Anomalies)
	}
}

func TestRecurseFilterAndLimits(t *testing.T) {
	e := open(t, classify.WithLimits(classify.Limits{MaxChildren: 2}))
	z := testkit.Zip(testkit.File{Name: "res/a", Data: []byte("1")}, testkit.File{Name: "b", Data: []byte("2")}, testkit.File{Name: "c", Data: []byte("3")})
	r := classifyOK(t, e, classify.Bytes(z))
	if len(r.Children) != 2 || r.Complete || !strings.Contains(strings.Join(r.Limitations, ";"), "MaxChildren") {
		t.Fatalf("MaxChildren: %+v", r)
	}
	e2 := open(t)
	r = classifyOK(t, e2, classify.Bytes(z), classify.Recurse(func(_ []string, c classify.Child) bool {
		return !strings.HasPrefix(c.Name, "res/")
	}))
	if len(r.Children) != 2 || child(r, "res/a") != nil {
		t.Fatalf("Recurse: %+v", r.Children)
	}
}

func TestSelfReferentialAndDeepNesting(t *testing.T) {
	e := open(t, classify.WithLimits(classify.Limits{MaxDepth: 3}))
	data := []byte("core")
	for i := 0; i < 6; i++ {
		data = testkit.Zip(testkit.File{Name: "n.zip", Data: data})
	}
	r := classifyOK(t, e, classify.Bytes(data))
	depth := 0
	for n := r; len(n.Children) > 0; n = n.Children[0].Result {
		depth++
	}
	lims := r.AllLimitations()
	if depth != 3 || len(lims) != 1 || !strings.HasPrefix(lims[0], "n.zip/n.zip/n.zip: derivation depth exceeds MaxDepth") {
		t.Fatalf("depth = %d limitations = %v", depth, lims)
	}
}

func TestGzipBombGuard(t *testing.T) {
	e := open(t, classify.WithLimits(classify.Limits{MaxExpansion: 10}))
	r := classifyOK(t, e, classify.Bytes(testkit.Gzip(make([]byte, 4<<20), "")))
	if len(r.Children) != 0 || !r.HasAnomaly("compression.expansion-limit") {
		t.Fatalf("bomb: %+v", r)
	}
}

func TestConcurrentClassify(t *testing.T) {
	e := open(t)
	inputs := [][]byte{testkit.Zip(testkit.File{Name: "a.json", Data: []byte("{}")}), testkit.PE(true, false), []byte("text"), testkit.Gzip([]byte("x"), "")}
	var wg sync.WaitGroup
	results := make([]string, 64)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := e.Classify(context.Background(), classify.Bytes(inputs[i%len(inputs)]))
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = r.Primary
		}()
	}
	wg.Wait()
	for i, p := range results {
		if p != results[i%len(inputs)] {
			t.Fatalf("result %d = %s, want %s", i, p, results[i%len(inputs)])
		}
	}
}

func TestCachedResultEqualsFresh(t *testing.T) {
	dir := t.TempDir()
	apk := testkit.Zip(testkit.File{Name: "AndroidManifest.xml", Data: testkit.AXML("a.b", true)}, testkit.File{Name: "inner.zip", Data: testkit.Zip(testkit.File{Name: "x.txt", Data: []byte("x")})})
	e1, _ := classify.Open(context.Background(), dir)
	fresh, _ := e1.Classify(context.Background(), classify.Bytes(apk))
	e2, _ := classify.Open(context.Background(), dir)
	cached, _ := e2.Classify(context.Background(), classify.Bytes(apk))
	a, _ := json.Marshal(fresh)
	b, _ := json.Marshal(cached)
	if !bytes.Equal(a, b) {
		t.Fatalf("cached result differs:\nfresh  %s\ncached %s", a, b)
	}
}

func TestClosedAndCancelled(t *testing.T) {
	e := open(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Classify(ctx, classify.Text("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled err = %v", err)
	}
	e.Close()
	if _, err := e.Classify(context.Background(), classify.Text("x")); !errors.Is(err, classify.ErrClosed) {
		t.Fatalf("closed err = %v", err)
	}
	if _, err := classify.Open(context.Background(), ""); err == nil {
		t.Fatal("Open accepted an empty workdir")
	}
}

func TestObserverEvents(t *testing.T) {
	var mu sync.Mutex
	var events []classify.Event
	e := open(t, classify.WithObserver(func(ev classify.Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	}))
	classifyOK(t, e, classify.Bytes(testkit.Zip(testkit.File{Name: "a.txt", Data: []byte("hi")})))
	mu.Lock()
	defer mu.Unlock()
	finals := map[string]int{}
	ids := map[uint64]bool{}
	for _, ev := range events {
		ids[ev.ID] = true
		if ev.Final {
			finals[ev.Op]++
			if ev.ParentID != 0 && !ids[ev.ParentID] {
				t.Fatalf("event %d has unknown parent %d", ev.ID, ev.ParentID)
			}
		}
	}
	if finals["classify"] != 1 || finals["node"] != 2 || finals["classifier"] == 0 {
		t.Fatalf("finals = %v", finals)
	}
	var root classify.Event
	for _, ev := range events {
		if ev.Op == "node" && ev.Final && root.ID == 0 {
			root = ev
		}
	}
	if root.Counters["bytes_read"] == 0 || root.Counters["children"] != 1 {
		t.Fatalf("node counters = %v", root.Counters)
	}
}
