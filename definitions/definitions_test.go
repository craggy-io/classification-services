package definitions_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/craggy-io/foundation-kit/bundle"
	"github.com/craggy-io/foundation-kit/bundle/bundletest"

	"github.com/craggy-io/classification-services/definitions"
	"github.com/craggy-io/classification-services/evidence"
)

const src = `"""Widgets.

Longer description."""
type("acme.w", parents = ["text"], ext = ["w"], priority = 2)
signature("acme.w", at(0, "5749"), at(4, b"!"), level = "recognised", id = "wi")
def _r(ctx):
    return None
classifier("w", produces = ["acme.w"], requires = ["text"], derives = True, run = _r)
test("t", hex = "57 49", expect = ["acme.w"], anomalies = ["x"])
`

func TestLoadDeclarations(t *testing.T) {
	m, err := definitions.Load(context.Background(), "acme", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if m.Doc != "Widgets." || len(m.Types) != 1 || m.Types[0].Priority != 2 || len(m.Classifiers) != 1 || len(m.Tests) != 1 {
		t.Fatalf("module = %+v", m)
	}
	sig := m.Signatures[0]
	if sig.ID != "acme:wi" || sig.Level != evidence.Recognised || len(sig.Patterns) != 2 {
		t.Fatalf("signature = %+v", sig)
	}
	c := m.Classifiers[0]
	if !c.Derives || c.Module != "acme" || c.Requires[0] != "text" {
		t.Fatalf("classifier = %+v", c)
	}
	if string(m.Tests[0].Data) != "WI" {
		t.Fatalf("test data = %q", m.Tests[0].Data)
	}
}

func TestLoadErrors(t *testing.T) {
	for _, bad := range []string{
		`type()`, `signature("a.b")`, `signature("a.b", "notapattern")`, `at(-1, "00")`,
		`classifier("x")`, `test("t", hex = "zz")`, `test("t", hex = "00", data = "x")`, `open("/etc/passwd")`,
		`load("x.star", "y")`, `signature("a.b", at(0, "00"), color = "red")`,
	} {
		if _, err := definitions.Load(context.Background(), "bad", []byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, name := range []string{"", "Upper", "../x", "a/b", "trailing-", strings.Repeat("a", 200)} {
		if definitions.ValidName(name) {
			t.Errorf("ValidName(%q)", name)
		}
	}
}

const manifest = `apiVersion: craggy.io/bundle/v1
metadata: {id: test.defs, version: 1.0.0}
contributions:
  - {id: widgets, kind: classify.module@1, path: mods/w.star}
  - {id: broken, kind: classify.module@1, path: mods/broken.star}
`

func compiler() bundle.AnyCompiler {
	return bundle.Compile(definitions.ModuleKind, definitions.Compile)
}

func TestCompileNamesModulesByContributionID(t *testing.T) {
	fsys := fstest.MapFS{
		"bundle.yaml":      {Data: []byte(strings.Replace(manifest, "  - {id: broken, kind: classify.module@1, path: mods/broken.star}\n", "", 1))},
		"mods/w.star":      {Data: []byte(src)},
		"mods/unused.star": {Data: []byte("def (")}, // not listed, so not loaded
	}
	cat := bundletest.Load(t, fsys, compiler())
	def, ok := bundle.Lookup(cat, definitions.ModuleKind, "widgets")
	if !ok || def.Value.Name != "widgets" || def.Value.Classifiers[0].Module != "widgets" || def.Value.Signatures[0].ID != "widgets:wi" {
		t.Fatalf("widgets = %+v, %v", def.Value, ok)
	}
}

func TestCompileErrorsAreDiagnosticsInTheFile(t *testing.T) {
	fsys := fstest.MapFS{
		"bundle.yaml":      {Data: []byte(manifest)},
		"mods/w.star":      {Data: []byte(src)},
		"mods/broken.star": {Data: []byte("type(\"a.b\")\n\nsignature(\"a.b\", \"notapattern\")\n")},
	}
	_, err := bundle.Load(context.Background(), bundle.Options{Sources: []bundle.Source{bundle.Embedded("test", fsys)}, Compilers: []bundle.AnyCompiler{compiler()}})
	var le *bundle.LoadError
	if !errors.As(err, &le) || len(le.Diagnostics) != 1 {
		t.Fatalf("err = %v", err)
	}
	d := le.Diagnostics[0]
	if d.Code != definitions.CodeInvalid || d.Contribution != "broken" || d.Path != "mods/broken.star" || d.Line != 3 || !strings.Contains(d.Message, "patterns must come from at()") {
		t.Fatalf("diagnostic = %+v", d)
	}

	// Every resolve error is reported, each at its own line.
	fsys["mods/broken.star"] = &fstest.MapFile{Data: []byte("x = nope\ny = alsonope\n")}
	_, err = bundle.Load(context.Background(), bundle.Options{Sources: []bundle.Source{bundle.Embedded("test", fsys)}, Compilers: []bundle.AnyCompiler{compiler()}})
	if !errors.As(err, &le) || len(le.Diagnostics) != 2 || le.Diagnostics[0].Line != 1 || le.Diagnostics[1].Line != 2 {
		t.Fatalf("err = %v (%+v)", err, le)
	}
}

func TestCompileRejectsInvalidModuleNames(t *testing.T) {
	fsys := fstest.MapFS{
		"bundle.yaml": {Data: []byte("apiVersion: craggy.io/bundle/v1\nmetadata: {id: test.defs, version: 1.0.0}\ncontributions:\n  - {id: Upper, kind: classify.module@1, path: u.star}\n")},
		"u.star":      {Data: []byte(`type("x.a")`)},
	}
	_, err := bundle.Load(context.Background(), bundle.Options{Sources: []bundle.Source{bundle.Embedded("test", fsys)}, Compilers: []bundle.AnyCompiler{compiler()}})
	bundletest.RequireCode(t, err, definitions.CodeInvalid)
}
