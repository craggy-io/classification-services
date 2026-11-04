package definitions_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/craggy-io/classification-services/definitions"
	"github.com/craggy-io/classification-services/evidence"
)

type memCache map[string][]byte

func (m memCache) Program(h string) ([]byte, bool) { b, ok := m[h]; return b, ok }
func (m memCache) PutProgram(h string, b []byte)   { m[h] = b }

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
	cache := memCache{}
	m, err := definitions.Load("acme", []byte(src), cache)
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
	if len(cache) != 1 {
		t.Fatal("compiled program not cached")
	}
	if m2, err := definitions.Load("acme", []byte(src), cache); err != nil || len(m2.Types) != 1 {
		t.Fatalf("load from compiled cache: %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	for _, bad := range []string{
		`type()`, `signature("a.b")`, `signature("a.b", "notapattern")`, `at(-1, "00")`,
		`classifier("x")`, `test("t", hex = "zz")`, `test("t", hex = "00", data = "x")`, `open("/etc/passwd")`,
		`load("x.star", "y")`, `signature("a.b", at(0, "00"), color = "red")`,
	} {
		if _, err := definitions.Load("bad", []byte(bad), nil); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, name := range []string{"", "Upper", "../x", "a/b", strings.Repeat("a", 200)} {
		if definitions.ValidName(name) {
			t.Errorf("ValidName(%q)", name)
		}
	}
}

func TestLoadFSRejectsDuplicateNames(t *testing.T) {
	fsys := fstest.MapFS{"a/m.star": {Data: []byte(`type("x.a")`)}, "b/m.star": {Data: []byte(`type("x.b")`)}}
	if _, err := definitions.LoadFS(fsys, nil); err == nil || !strings.Contains(err.Error(), "defined by both") {
		t.Fatalf("err = %v", err)
	}
}
