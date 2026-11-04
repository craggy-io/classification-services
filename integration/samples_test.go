package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/craggy-io/classification-services/classify"
)

// The samples folder is documented in samples/README.md; keep the two in step.
func TestSamples(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join("..", "samples")
	want := map[string]struct {
		primary string
		anomaly string
	}{
		"app.apk": {"android.apk", ""}, "debug.apk": {"android.apk", "android.debuggable"},
		"slip.zip": {"archive.zip", "zip.path-traversal"}, "elf-with-zip": {"executable.elf", "polyglot"},
		"invoice.pdf": {"executable.pe", "extension-mismatch"}, "form.pdf": {"document.pdf", "pdf.javascript"},
		"report.docm": {"document.docx", "document.macros"}, "legacy.xls": {"document.xls", "document.macros"},
		"plugin.dll": {"executable.dotnet", ""}, "logs.tar.gz": {"compression.gzip", ""},
		"capture.pcap": {"network.pcap", ""}, "module.wasm": {"executable.wasm", ""},
		"token.jwt": {"crypto.jwt", "crypto.jwt-unsigned"}, "encoded.b64": {"encoding.base64", ""},
		"config.json": {"data.json", ""}, "run.sh": {"source.python", ""}, "notes.txt": {"text", ""},
		"current.wdg": {"text", ""}, "legacy.wdg": {"text", ""}, "widgets.star": {"text", ""},
		"README.md": {"text", ""},
	}
	e, err := classify.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != len(want) {
		t.Fatalf("samples has %d files, the test expects %d", len(ents), len(want))
	}
	for _, ent := range ents {
		w, ok := want[ent.Name()]
		if !ok {
			t.Fatalf("unexpected sample %s", ent.Name())
		}
		r, err := e.Classify(ctx, classify.File(filepath.Join(dir, ent.Name())))
		if err != nil {
			t.Fatal(err)
		}
		if r.Primary != w.primary || (w.anomaly != "" && !r.HasAnomaly(w.anomaly)) {
			t.Errorf("%s: primary %s anomalies %v; want %s with %q", ent.Name(), r.Primary, r.Anomalies, w.primary, w.anomaly)
		}
	}
	src, _ := os.ReadFile(filepath.Join(dir, "widgets.star"))
	rep, err := e.Check(ctx, "widgets", src)
	if err != nil || !rep.Passed() {
		t.Fatalf("widgets.star: %+v %v", rep, err)
	}
	r, _ := e.Classify(ctx, classify.File(filepath.Join(dir, "encoded.b64")), classify.WithDepth(classify.Deep))
	if len(r.Children) != 1 || r.Children[0].Primary != "data.json" {
		t.Fatalf("encoded.b64 at Deep: %+v", r.Children)
	}
}
