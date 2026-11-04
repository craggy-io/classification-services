package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/craggy-io/classification-services/internal/testkit"
)

func cli(t *testing.T, workdir string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append(args, "--workdir", workdir), &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLI(t *testing.T) {
	wd := t.TempDir()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"x": 1}`), 0o644)
	os.WriteFile(filepath.Join(dir, "evil.zip"), testkit.Zip(testkit.File{Name: "../x", Data: []byte("x")}), 0o644)

	code, out, errs := cli(t, wd, dir, "--tree", "--fail-on", "critical")
	if code != exitAnomaly || !strings.Contains(out, "a.json: data.json (validated)") || !strings.Contains(out, "! critical zip.path-traversal") {
		t.Fatalf("classify: code=%d\n%s%s", code, out, errs)
	}
	code, out, _ = cli(t, wd, "classify", "--json", "--explain", "data.json", filepath.Join(dir, "a.json"))
	var jr jsonResult
	if code != exitOK || json.Unmarshal([]byte(out), &jr) != nil || jr.Result.Primary != "data.json" || jr.Explanation == nil || !jr.Explanation.Holds {
		t.Fatalf("json: code=%d %s", code, out)
	}

	def := filepath.Join(dir, "acme.star")
	os.WriteFile(def, []byte(`type("acme", abstract = True)
type("acme.thing", parents = ["acme", "data.json"])
def _t(ctx):
    if "thing" in ctx.json():
        return ctx.match("acme.thing", level = "validated")
classifier("thing", produces = ["acme.thing"], requires = ["data.json"], run = _t)
test("thing", data = '{"thing": 1}', primary = "acme.thing")
`), 0o644)
	os.WriteFile(filepath.Join(dir, "t.json"), []byte(`{"thing": 2}`), 0o644)
	cli(t, wd, filepath.Join(dir, "t.json"))
	if code, out, errs := cli(t, wd, "check", def); code != exitOK || !strings.Contains(out, "ok   thing") {
		t.Fatalf("check: %d %s %s", code, out, errs)
	}
	if code, out, _ := cli(t, wd, "preview", def); code != exitOK || !strings.Contains(out, "t.json: data.json -> acme.thing") {
		t.Fatalf("preview: %d %s", code, out)
	}
	if code, _, errs := cli(t, wd, "define", def); code != exitOK {
		t.Fatalf("define: %s", errs)
	}
	if _, out, _ := cli(t, wd, "definitions"); !strings.Contains(out, "acme") {
		t.Fatalf("definitions: %s", out)
	}
	if _, out, _ := cli(t, wd, "types", "acme"); !strings.Contains(out, "acme.thing") {
		t.Fatalf("types: %s", out)
	}
	if code, out, _ := cli(t, wd, "test"); code != exitOK || !strings.Contains(out, "ok   acme / thing") {
		t.Fatalf("test: %d %s", code, out)
	}
	if code, _, _ := cli(t, wd, "remove", "acme"); code != exitOK {
		t.Fatal("remove failed")
	}
	if code, out, _ := cli(t, wd, "maintain"); code != exitOK || !strings.Contains(out, "removed") {
		t.Fatalf("maintain: %s", out)
	}
	if cmd, rest := command([]string{"--workdir", "check", "types", "x"}); cmd != "types" || len(rest) != 3 {
		t.Fatalf("command = %s %v", cmd, rest)
	}
	if code, _, _ := cli(t, wd); code != exitError {
		t.Fatal("no paths should be an error")
	}
}
