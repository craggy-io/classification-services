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
		primary   string
		anomalies []string
	}{
		"app.apk": {"android.apk", nil}, "debug.apk": {"android.apk", []string{"android.debuggable", "android.unsigned"}},
		"slip.zip": {"archive.zip", []string{"zip.path-traversal"}}, "elf-with-zip": {"executable.elf", []string{"executable.overlay", "polyglot", "zip.prepended-data"}},
		"invoice.pdf": {"executable.pe", []string{"extension-mismatch"}}, "form.pdf": {"document.pdf", []string{"pdf.auto-action", "pdf.javascript"}},
		"report.docm": {"document.docx", []string{"document.macros"}}, "legacy.xls": {"document.xls", []string{"document.macros"}},
		"plugin.dll": {"executable.dotnet", nil}, "logs.tar.gz": {"compression.gzip", nil},
		"capture.pcap": {"network.pcap", nil}, "module.wasm": {"executable.wasm", nil},
		"token.jwt": {"crypto.jwt", []string{"crypto.jwt-unsigned"}}, "encoded.b64": {"encoding.base64", nil},
		"config.json": {"data.json", nil}, "run.sh": {"source.python", nil}, "notes.txt": {"text", nil},
		"current.wdg": {"text", nil}, "legacy.wdg": {"text", nil}, "widgets.star": {"text", nil},
		"README.md": {"text", nil},
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
		var codes []string
		for _, a := range r.Anomalies {
			codes = append(codes, a.Code)
		}
		wantCodes := map[string]bool{}
		for _, a := range w.anomalies {
			wantCodes[a] = true
		}
		exact := len(codes) == len(wantCodes)
		for _, c := range codes {
			if !wantCodes[c] {
				exact = false
			}
		}
		if r.Primary != w.primary || !exact {
			t.Errorf("%s: primary %s anomalies %v; want %s with exactly %v", ent.Name(), r.Primary, codes, w.primary, w.anomalies)
		}
	}
	src, _ := os.ReadFile(filepath.Join(dir, "widgets.star"))
	rep, err := e.Check(ctx, "widgets", src)
	if err != nil || !rep.Passed() {
		t.Fatalf("widgets.star: %+v %v", rep, err)
	}
	r, err := e.Classify(ctx, classify.File(filepath.Join(dir, "encoded.b64")), classify.WithDepth(classify.Deep))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Children) != 1 || r.Children[0].Primary != "data.json" {
		t.Fatalf("encoded.b64 at Deep: %+v", r.Children)
	}
}
