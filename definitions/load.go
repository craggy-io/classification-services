// Package definitions loads Starlark definition modules. One module is a
// single self-describing .star file whose top-level calls declare types,
// signatures, classifiers and inline tests; nothing reads content at load
// time:
//
//	type("archive.jar", parents = ["archive.zip"], mime = "application/java-archive", ext = ["jar"])
//	signature("archive.jar", at(0, "504b0304"))
//
//	def _jar(ctx):
//	    z = ctx.view.zip()
//	    if not z.has("META-INF/MANIFEST.MF"):
//	        return ctx.reject("archive.jar")
//	    return ctx.match("archive.jar", level = "validated")
//
//	classifier("jar", produces = ["archive.jar"], requires = ["archive.zip"], run = _jar)
//	test("manifest-only jar", hex = "504b0304...", expect = ["archive.jar"])
//
// Modules ship in bundles: a folder (or embedded file system) whose
// bundle.yaml lists each module as a contribution of ModuleKind
// (classify.module@1). The contribution ID is the module name and its path
// the .star file; a folder without a bundle.yaml is not loaded. Compile is
// the kind's compiler, which the classify engine passes to bundle.Load.
//
// Starlark is used for determinism and cacheability, not as a sandbox:
// definitions are trusted code. Scripts get no file system or network
// access, a step limit stops runaway loops, and every content read goes
// through the engine's budgeted reader.
package definitions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"go.starlark.net/lib/json"
	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	"github.com/craggy-io/foundation-kit/bundle"
	"github.com/craggy-io/foundation-kit/kind"

	"github.com/craggy-io/classification-services/catalog"
	"github.com/craggy-io/classification-services/evidence"
	"github.com/craggy-io/classification-services/signatures"
)

// Module is a parsed definition module.
type Module struct {
	Name        string
	Source      []byte
	SourceHash  string
	Types       []catalog.TypeInfo
	Signatures  []signatures.Rule
	Classifiers []*Classifier
	Tests       []Test
}

// Classifier is a Starlark classifier declared by a module.
type Classifier struct {
	ID       string
	Produces []string
	Requires []string
	Derives  bool
	Module   string
	fn       starlark.Callable
}

// Test is an inline expectation declared with test(). The engine runs tests
// in Check before a module is installed.
type Test struct {
	Name     string
	Data     []byte
	Text     bool     // classify as a Text source
	FileName string   // source name hint
	Expect   []string // types that must hold
	Absent   []string // types that must not hold
	Primary  string   // expected primary type, if set
	// Anomalies lists anomaly codes that must be reported.
	Anomalies []string
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9_.-]*[a-z0-9])?$`)

// ValidName reports whether name is a valid module name: lower-case letters,
// digits, '_', '.' and '-', starting and ending with a letter or digit, so
// that it is also a valid bundle contribution ID and file name.
func ValidName(name string) bool {
	return len(name) <= 128 && nameRe.MatchString(name) && !strings.Contains(name, "..")
}

var predeclared = map[string]bool{
	"type": true, "signature": true, "classifier": true, "test": true,
	"at": true, "base64": true, "hex": true, "json": true,
}

// ModuleKind is the bundle kind of a definition module. It is global: a
// module is named by its contribution ID alone, so two bundles defining the
// same module name is a bundle.id_conflict unless a bundle override settles
// it. Read definitions with bundle.All or bundle.Lookup.
var ModuleKind = kind.New[*Module]("classify.module", 1, kind.Global())

// CodeInvalid is the diagnostic code for a module that does not parse or
// whose top level fails.
const CodeInvalid bundle.Code = "classify.module_invalid"

// Compile is ModuleKind's bundle compiler. The contribution ID is the
// module name, and its path names the .star file in the bundle. Compiling
// runs the module's top level, which only declares; it reads no content
// and has no side effects. Errors become diagnostics positioned in the
// file.
func Compile(ctx context.Context, c bundle.Contribution) (bundle.Compiled[*Module], []bundle.Diagnostic) {
	diag := func(line, col int, msg string) bundle.Diagnostic {
		return bundle.Diagnostic{Code: CodeInvalid, Path: c.Path, Line: line, Column: col, Message: msg}
	}
	if !ValidName(c.Ref.ID) {
		return bundle.Compiled[*Module]{}, []bundle.Diagnostic{diag(0, 0, fmt.Sprintf("%q is not a valid module name: use lower-case letters, digits, '_', '.' and '-', starting and ending with a letter or digit", c.Ref.ID))}
	}
	src, err := fs.ReadFile(c.Files, c.Path)
	if err != nil {
		return bundle.Compiled[*Module]{}, []bundle.Diagnostic{diag(0, 0, err.Error())}
	}
	mod, err := load(ctx, c.Ref.ID, c.Path, src)
	if err != nil {
		return bundle.Compiled[*Module]{}, diagnostics(err, c.Path, diag)
	}
	return bundle.Compiled[*Module]{Value: mod}, nil
}

// diagnostics positions a load error in file: every resolve error, a syntax
// error, or the innermost frame of a failing top level that is in file.
func diagnostics(err error, file string, diag func(line, col int, msg string) bundle.Diagnostic) []bundle.Diagnostic {
	var (
		list resolve.ErrorList
		se   syntax.Error
		ee   *starlark.EvalError
	)
	switch {
	case errors.As(err, &list):
		out := make([]bundle.Diagnostic, 0, len(list))
		for _, e := range list {
			out = append(out, diag(int(e.Pos.Line), int(e.Pos.Col), e.Msg))
		}
		return out
	case errors.As(err, &se):
		return []bundle.Diagnostic{diag(int(se.Pos.Line), int(se.Pos.Col), se.Msg)}
	case errors.As(err, &ee):
		for i := len(ee.CallStack) - 1; i >= 0; i-- {
			if pos := ee.CallStack[i].Pos; pos.Filename() == file {
				return []bundle.Diagnostic{diag(int(pos.Line), int(pos.Col), ee.Msg)}
			}
		}
		return []bundle.Diagnostic{diag(0, 0, ee.Msg)}
	}
	return []bundle.Diagnostic{diag(0, 0, err.Error())}
}

// Load parses source as the module name and runs its top level, collecting
// its declarations. ctx stops the top-level execution (a step limit also
// applies). Installed and shipped modules are read from bundles through
// Compile; Load is for a module held in memory.
func Load(ctx context.Context, name string, source []byte) (*Module, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("definitions: invalid module name %q", name)
	}
	return load(ctx, name, name+".star", source)
}

func load(ctx context.Context, name, file string, source []byte) (*Module, error) {
	sum := sha256.Sum256(source)
	mod := &Module{Name: name, Source: bytes.Clone(source), SourceHash: hex.EncodeToString(sum[:])}
	_, prog, err := starlark.SourceProgram(file, source, func(n string) bool { return predeclared[n] })
	if err != nil {
		return nil, fmt.Errorf("definitions: %s: %w", name, err)
	}

	d := &declarer{mod: mod}
	env := starlark.StringDict{
		"type":       builtin("type", d.typ),
		"signature":  builtin("signature", d.signature),
		"classifier": builtin("classifier", d.classifier),
		"test":       builtin("test", d.test),
		"at":         builtin("at", at),
		"base64":     base64Module(),
		"hex":        hexModule(),
		"json":       json.Module,
	}
	thread := &starlark.Thread{Name: "load:" + name}
	thread.SetMaxExecutionSteps(10_000_000)
	stop := context.AfterFunc(ctx, func() { thread.Cancel(context.Cause(ctx).Error()) })
	defer stop()
	globals, err := prog.Init(thread, env)
	if err != nil {
		return nil, fmt.Errorf("definitions: %s: %w", name, err)
	}
	// Frozen globals make classifier functions safe to call concurrently.
	for _, v := range globals {
		v.Freeze()
	}
	// A classifier function need not be a global (run = make()), so freeze
	// each one directly to freeze its closure freevars and defaults too.
	for _, c := range mod.Classifiers {
		c.fn.Freeze()
		c.Module = name
	}
	return mod, nil
}

type declarer struct{ mod *Module }

func (d *declarer) typ(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, mime, description string
	var parents, ext starlark.Value
	var priority int
	var abstract bool
	if err := starlark.UnpackArgs("type", args, kwargs,
		"name", &name, "parents?", &parents, "mime?", &mime, "ext?", &ext,
		"priority?", &priority, "description?", &description, "abstract?", &abstract); err != nil {
		return nil, err
	}
	ti := catalog.TypeInfo{Name: name, MIME: mime, Priority: priority, Description: description, Abstract: abstract}
	var err error
	if ti.Parents, err = stringList(parents); err != nil {
		return nil, fmt.Errorf("type %q parents: %w", name, err)
	}
	if ti.Ext, err = stringList(ext); err != nil {
		return nil, fmt.Errorf("type %q ext: %w", name, err)
	}
	if len(ti.Parents) == 0 && name != catalog.Bytes {
		ti.Parents = []string{catalog.Bytes}
	}
	d.mod.Types = append(d.mod.Types, ti)
	return starlark.None, nil
}

// patternValue carries an at() pattern.
type patternValue struct{ p signatures.Pattern }

func (p *patternValue) String() string        { return "at(" + p.p.Canonical() + ")" }
func (p *patternValue) Type() string          { return "pattern" }
func (p *patternValue) Truth() starlark.Bool  { return starlark.True }
func (p *patternValue) Freeze()               {}
func (p *patternValue) Hash() (uint32, error) { return starlark.String(p.String()).Hash() }

func at(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var offset int64
	var pattern starlark.Value
	if err := starlark.UnpackPositionalArgs("at", args, kwargs, 2, &offset, &pattern); err != nil {
		return nil, err
	}
	switch p := pattern.(type) {
	case starlark.String:
		pat, err := signatures.Hex(offset, string(p))
		if err != nil {
			return nil, fmt.Errorf("at: %w", err)
		}
		return &patternValue{p: pat}, nil
	case starlark.Bytes:
		if offset < 0 {
			return nil, fmt.Errorf("at: negative offset %d", offset)
		}
		if len(p) == 0 {
			return nil, fmt.Errorf("at: empty pattern")
		}
		return &patternValue{p: signatures.Literal(offset, []byte(p))}, nil
	}
	return nil, fmt.Errorf("at: pattern must be a hex string or bytes, got %s", pattern.Type())
}

func (d *declarer) signature(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("signature: want (type, at(...), ...)")
	}
	typ, ok := args[0].(starlark.String)
	if !ok || typ == "" {
		return nil, fmt.Errorf("signature: type must be a non-empty string")
	}
	r := signatures.Rule{Type: string(typ), Level: evidence.Candidate, Module: d.mod.Name}
	for _, a := range args[1:] {
		pv, ok := a.(*patternValue)
		if !ok {
			return nil, fmt.Errorf("signature: patterns must come from at(), got %s", a.Type())
		}
		r.Patterns = append(r.Patterns, pv.p)
	}
	kw := kwargMap(kwargs)
	for k := range kw {
		if k != "level" && k != "id" {
			return nil, fmt.Errorf("signature: unexpected keyword %q", k)
		}
	}
	if v, ok := kw["level"]; ok {
		s, ok := v.(starlark.String)
		if !ok {
			return nil, fmt.Errorf("signature: level must be a string")
		}
		l, err := evidence.ParseLevel(string(s))
		if err != nil {
			return nil, fmt.Errorf("signature: %w", err)
		}
		r.Level = l
	}
	r.ID = fmt.Sprintf("%s:%s#%d", d.mod.Name, typ, len(d.mod.Signatures))
	if v, ok := kw["id"]; ok {
		s, ok := v.(starlark.String)
		if !ok {
			return nil, fmt.Errorf("signature: id must be a string")
		}
		r.ID = d.mod.Name + ":" + string(s)
	}
	d.mod.Signatures = append(d.mod.Signatures, r)
	return starlark.None, nil
}

func (d *declarer) classifier(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	var produces, requires starlark.Value
	var derives bool
	var run starlark.Callable
	if err := starlark.UnpackArgs("classifier", args, kwargs,
		"id", &id, "run", &run, "produces?", &produces, "requires?", &requires, "derives?", &derives); err != nil {
		return nil, err
	}
	if id == "" {
		return nil, fmt.Errorf("classifier: id must be non-empty")
	}
	c := &Classifier{ID: id, Derives: derives, fn: run}
	var err error
	if c.Produces, err = stringList(produces); err != nil {
		return nil, fmt.Errorf("classifier %q produces: %w", id, err)
	}
	if c.Requires, err = stringList(requires); err != nil {
		return nil, fmt.Errorf("classifier %q requires: %w", id, err)
	}
	if len(c.Requires) == 0 {
		c.Requires = []string{catalog.Bytes}
	}
	d.mod.Classifiers = append(d.mod.Classifiers, c)
	return starlark.None, nil
}

func (d *declarer) test(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, hexData, filename, primary string
	var data, expect, absent, anomalies starlark.Value
	var text bool
	if err := starlark.UnpackArgs("test", args, kwargs,
		"name", &name, "data?", &data, "hex?", &hexData, "text?", &text, "filename?", &filename,
		"expect?", &expect, "absent?", &absent, "primary?", &primary, "anomalies?", &anomalies); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("test: name must be non-empty")
	}
	t := Test{Name: name, Text: text, FileName: filename, Primary: primary}
	var err error
	switch {
	case hexData != "" && data != nil:
		return nil, fmt.Errorf("test %q: give data or hex, not both", name)
	case hexData != "":
		if t.Data, err = hex.DecodeString(strings.Join(strings.Fields(hexData), "")); err != nil {
			return nil, fmt.Errorf("test %q hex: %w", name, err)
		}
	case data != nil:
		if t.Data, err = toBytes(data); err != nil {
			return nil, fmt.Errorf("test %q data: %w", name, err)
		}
	}
	if t.Expect, err = stringList(expect); err != nil {
		return nil, fmt.Errorf("test %q expect: %w", name, err)
	}
	if t.Absent, err = stringList(absent); err != nil {
		return nil, fmt.Errorf("test %q absent: %w", name, err)
	}
	if t.Anomalies, err = stringList(anomalies); err != nil {
		return nil, fmt.Errorf("test %q anomalies: %w", name, err)
	}
	if len(t.Expect)+len(t.Absent)+len(t.Anomalies) == 0 && t.Primary == "" {
		return nil, fmt.Errorf("test %q: no expectations (give expect, absent, primary or anomalies)", name)
	}
	d.mod.Tests = append(d.mod.Tests, t)
	return starlark.None, nil
}
