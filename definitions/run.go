package definitions

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"go.starlark.net/starlark"

	"github.com/craggy-io/classification-services/evidence"
	"github.com/craggy-io/classification-services/views"
)

// Host is the engine-side access a running classifier gets. Every read is
// budgeted and every view memoised by the engine.
type Host interface {
	Size() int64
	Digest() string
	Name() string
	ReadRange(off, n int64) ([]byte, error)
	JSON(limit int64) (any, error)
	View(name string) (any, error)
	// Facet returns the metadata of an established type and whether it holds.
	Facet(t string) (map[string]any, bool)
}

// Limits bounds one classifier run.
type Limits struct {
	Steps           uint64 // Starlark execution steps; zero selects 4,000,000
	MaxDerivedBytes int64  // cap on one derived child
}

// Assertion is a type match or rejection.
type Assertion struct {
	Type     string
	Level    evidence.Level
	Metadata map[string]any
	Reject   bool
}

// Derived is derived content: Data, or a byte range of the input when
// Length > 0.
type Derived struct {
	Name        string
	Data        []byte
	Offset      int64
	Length      int64
	Speculative bool
}

// Output is everything one classifier run produced.
type Output struct {
	Assertions []Assertion
	Derived    []Derived
	Anomalies  []evidence.Anomaly
}

// assertionValue is what ctx.match and ctx.reject return. Returning it from
// run is allowed but not required: the call already recorded it.
type assertionValue struct{ a Assertion }

func (v *assertionValue) String() string {
	if v.a.Reject {
		return "<reject " + v.a.Type + ">"
	}
	return "<match " + v.a.Type + ">"
}
func (v *assertionValue) Type() string          { return "assertion" }
func (v *assertionValue) Truth() starlark.Bool  { return starlark.True }
func (v *assertionValue) Freeze()               {}
func (v *assertionValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable type: assertion") }

// Run executes the classifier against host. Context cancellation and the
// step limit both stop the script; the error says which.
func (c *Classifier) Run(ctx context.Context, host Host, lim Limits) (Output, error) {
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	steps := lim.Steps
	if steps == 0 {
		steps = 4_000_000
	}
	r := &run{host: host, lim: lim, derives: c.Derives, id: c.ID}
	thread := &starlark.Thread{Name: "classifier:" + c.ID}
	thread.SetMaxExecutionSteps(steps)
	stop := context.AfterFunc(ctx, func() { thread.Cancel(context.Cause(ctx).Error()) })
	defer stop()
	ret, err := starlark.Call(thread, c.fn, starlark.Tuple{r.ctxValue()}, nil)
	if err != nil {
		return Output{}, err
	}
	if err := r.collectReturn(ret); err != nil {
		return Output{}, fmt.Errorf("classifier %q: %w", c.ID, err)
	}
	return r.out, nil
}

type run struct {
	host     Host
	lim      Limits
	derives  bool
	id       string
	out      Output
	recorded map[*assertionValue]bool
}

func (r *run) record(a Assertion) *assertionValue {
	v := &assertionValue{a: a}
	if r.recorded == nil {
		r.recorded = map[*assertionValue]bool{}
	}
	r.recorded[v] = true
	r.out.Assertions = append(r.out.Assertions, a)
	return v
}

func (r *run) collectReturn(ret starlark.Value) error {
	add := func(v starlark.Value) error {
		av, ok := v.(*assertionValue)
		if !ok {
			return fmt.Errorf("returned %s, want an assertion, a list of assertions, or None", v.Type())
		}
		if !r.recorded[av] {
			r.recorded[av] = true
			r.out.Assertions = append(r.out.Assertions, av.a)
		}
		return nil
	}
	switch t := ret.(type) {
	case starlark.NoneType:
		return nil
	case *starlark.List:
		for i := 0; i < t.Len(); i++ {
			if err := add(t.Index(i)); err != nil {
				return err
			}
		}
		return nil
	case starlark.Tuple:
		for _, v := range t {
			if err := add(v); err != nil {
				return err
			}
		}
		return nil
	}
	return add(ret)
}

func (r *run) read(off, n int64) ([]byte, error) {
	if off < 0 || n < 0 {
		return nil, fmt.Errorf("negative range (%d, %d)", off, n)
	}
	return r.host.ReadRange(off, n)
}

func levelArg(v starlark.Value, def evidence.Level) (evidence.Level, error) {
	if v == nil {
		return def, nil
	}
	s, ok := v.(starlark.String)
	if !ok {
		return 0, fmt.Errorf("level must be a string")
	}
	return evidence.ParseLevel(string(s))
}

func (r *run) ctxValue() starlark.Value {
	h := r.host
	unsigned := func(name string, width int, bo binary.ByteOrder) *starlark.Builtin {
		return builtin(name, func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var off int64
			if err := starlark.UnpackPositionalArgs(name, args, kwargs, 1, &off); err != nil {
				return nil, err
			}
			b, err := r.read(off, int64(width))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if len(b) < width {
				return nil, fmt.Errorf("%s: read past end of input at offset %d", name, off)
			}
			switch width {
			case 1:
				return starlark.MakeInt(int(b[0])), nil
			case 2:
				return starlark.MakeInt(int(bo.Uint16(b))), nil
			case 4:
				return starlark.MakeUint64(uint64(bo.Uint32(b))), nil
			}
			return starlark.MakeUint64(bo.Uint64(b)), nil
		})
	}
	limited := func(name string, fn func(limit int64) (starlark.Value, error)) *starlark.Builtin {
		return builtin(name, func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			limit := h.Size()
			if err := starlark.UnpackArgs(name, args, kwargs, "limit?", &limit); err != nil {
				return nil, err
			}
			return fn(max(limit, 0))
		})
	}
	attrs := map[string]starlark.Value{
		"size":   starlark.MakeInt64(h.Size()),
		"digest": starlark.String(h.Digest()),
		"name":   starlark.String(h.Name()),
		"prefix": limited("ctx.prefix", func(n int64) (starlark.Value, error) {
			b, err := r.read(0, n)
			return starlark.Bytes(string(b)), err
		}),
		"text": limited("ctx.text", func(n int64) (starlark.Value, error) {
			b, err := r.read(0, n)
			return starlark.String(b), err
		}),
		"json": limited("ctx.json", func(n int64) (starlark.Value, error) {
			v, err := h.JSON(n)
			if err != nil {
				return nil, fmt.Errorf("ctx.json: %w", err)
			}
			return fromGo(v), nil
		}),
		"read": builtin("ctx.read", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var off, n int64
			if err := starlark.UnpackPositionalArgs("ctx.read", args, kwargs, 2, &off, &n); err != nil {
				return nil, err
			}
			b, err := r.read(off, n)
			return starlark.Bytes(string(b)), err
		}),
		"u8":    unsigned("ctx.u8", 1, binary.LittleEndian),
		"u16le": unsigned("ctx.u16le", 2, binary.LittleEndian),
		"u16be": unsigned("ctx.u16be", 2, binary.BigEndian),
		"u32le": unsigned("ctx.u32le", 4, binary.LittleEndian),
		"u32be": unsigned("ctx.u32be", 4, binary.BigEndian),
		"u64le": unsigned("ctx.u64le", 8, binary.LittleEndian),
		"u64be": unsigned("ctx.u64be", 8, binary.BigEndian),
		"find":  builtin("ctx.find", r.find),
		"facet": builtin("ctx.facet", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var t string
			if err := starlark.UnpackPositionalArgs("ctx.facet", args, kwargs, 1, &t); err != nil {
				return nil, err
			}
			md, ok := h.Facet(t)
			if !ok {
				return starlark.None, nil
			}
			if md == nil {
				md = map[string]any{}
			}
			return fromGo(md), nil
		}),
		"has": builtin("ctx.has", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var t string
			if err := starlark.UnpackPositionalArgs("ctx.has", args, kwargs, 1, &t); err != nil {
				return nil, err
			}
			_, ok := h.Facet(t)
			return starlark.Bool(ok), nil
		}),
		"match":        builtin("ctx.match", r.match),
		"reject":       builtin("ctx.reject", r.reject),
		"anomaly":      builtin("ctx.anomaly", r.anomaly),
		"derive":       builtin("ctx.derive", r.derive),
		"derive_range": builtin("ctx.derive_range", r.deriveRange),
		"derive_entry": builtin("ctx.derive_entry", r.deriveEntry),
		"view":         r.viewsValue(),
	}
	return newObject("ctx", attrs)
}

func (r *run) find(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var needleV starlark.Value
	start, limit := int64(0), r.host.Size()
	if err := starlark.UnpackArgs("ctx.find", args, kwargs, "needle", &needleV, "start?", &start, "limit?", &limit); err != nil {
		return nil, err
	}
	needle, err := toBytes(needleV)
	if err != nil {
		return nil, fmt.Errorf("ctx.find: %w", err)
	}
	if len(needle) == 0 {
		return starlark.MakeInt64(start), nil
	}
	end := min(start+limit, r.host.Size())
	const chunk = 64 << 10
	var tail []byte
	for pos := max(start, 0); pos < end; {
		n := min(int64(chunk), end-pos)
		b, err := r.read(pos, n)
		if err != nil {
			return nil, err
		}
		window := append(tail, b...)
		if i := bytes.Index(window, needle); i >= 0 {
			return starlark.MakeInt64(pos - int64(len(tail)) + int64(i)), nil
		}
		keep := min(len(needle)-1, len(window))
		tail = append([]byte(nil), window[len(window)-keep:]...)
		pos += n
	}
	return starlark.MakeInt(-1), nil
}

func (r *run) match(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("ctx.match: want (type, level=..., **metadata)")
	}
	t, ok := args[0].(starlark.String)
	if !ok {
		return nil, fmt.Errorf("ctx.match: type must be a string")
	}
	a := Assertion{Type: string(t), Level: evidence.Recognised}
	for k, v := range kwargMap(kwargs) {
		if k == "level" {
			l, err := levelArg(v, evidence.Recognised)
			if err != nil {
				return nil, fmt.Errorf("ctx.match: %w", err)
			}
			a.Level = l
			continue
		}
		if a.Metadata == nil {
			a.Metadata = map[string]any{}
		}
		a.Metadata[k] = toGo(v)
	}
	return r.record(a), nil
}

func (r *run) reject(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var t string
	var level starlark.Value
	if err := starlark.UnpackArgs("ctx.reject", args, kwargs, "type", &t, "level?", &level); err != nil {
		return nil, err
	}
	l, err := levelArg(level, evidence.Validated)
	if err != nil {
		return nil, fmt.Errorf("ctx.reject: %w", err)
	}
	return r.record(Assertion{Type: t, Level: l, Reject: true}), nil
}

func (r *run) anomaly(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("ctx.anomaly: want (code, severity=..., message=..., **metadata)")
	}
	code, ok := args[0].(starlark.String)
	if !ok || code == "" {
		return nil, fmt.Errorf("ctx.anomaly: code must be a non-empty string")
	}
	a := evidence.Anomaly{Code: string(code), By: r.id}
	for k, v := range kwargMap(kwargs) {
		switch k {
		case "severity":
			s, ok := v.(starlark.String)
			if !ok {
				return nil, fmt.Errorf("ctx.anomaly: severity must be a string")
			}
			sev, err := evidence.ParseSeverity(string(s))
			if err != nil {
				return nil, fmt.Errorf("ctx.anomaly: %w", err)
			}
			a.Severity = sev
		case "message":
			s, ok := v.(starlark.String)
			if !ok {
				return nil, fmt.Errorf("ctx.anomaly: message must be a string")
			}
			a.Message = string(s)
		default:
			if a.Metadata == nil {
				a.Metadata = map[string]any{}
			}
			a.Metadata[k] = toGo(v)
		}
	}
	r.out.Anomalies = append(r.out.Anomalies, a)
	return starlark.None, nil
}

func (r *run) requireDerives(name string) error {
	if !r.derives {
		return fmt.Errorf("%s: classifier %q is not declared with derives = True", name, r.id)
	}
	return nil
}

func (r *run) derive(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := r.requireDerives("ctx.derive"); err != nil {
		return nil, err
	}
	var name string
	var data starlark.Value
	var speculative bool
	if err := starlark.UnpackArgs("ctx.derive", args, kwargs, "name", &name, "data", &data, "speculative?", &speculative); err != nil {
		return nil, err
	}
	b, err := toBytes(data)
	if err != nil {
		return nil, fmt.Errorf("ctx.derive: %w", err)
	}
	if r.lim.MaxDerivedBytes > 0 && int64(len(b)) > r.lim.MaxDerivedBytes {
		return nil, fmt.Errorf("ctx.derive: %q exceeds MaxDerivedBytes", name)
	}
	r.out.Derived = append(r.out.Derived, Derived{Name: name, Data: bytes.Clone(b), Speculative: speculative})
	return starlark.None, nil
}

func (r *run) deriveRange(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := r.requireDerives("ctx.derive_range"); err != nil {
		return nil, err
	}
	var name string
	var off, n int64
	var speculative bool
	if err := starlark.UnpackArgs("ctx.derive_range", args, kwargs, "name", &name, "offset", &off, "length", &n, "speculative?", &speculative); err != nil {
		return nil, err
	}
	if off < 0 || n <= 0 || off+n > r.host.Size() {
		return nil, fmt.Errorf("ctx.derive_range: range (%d, %d) outside the input", off, n)
	}
	r.out.Derived = append(r.out.Derived, Derived{Name: name, Offset: off, Length: n, Speculative: speculative})
	return starlark.None, nil
}

func (r *run) deriveEntry(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := r.requireDerives("ctx.derive_entry"); err != nil {
		return nil, err
	}
	var zipV, entryV starlark.Value
	var speculative bool
	if err := starlark.UnpackArgs("ctx.derive_entry", args, kwargs, "zip", &zipV, "entry", &entryV, "speculative?", &speculative); err != nil {
		return nil, err
	}
	var name string
	switch e := entryV.(type) {
	case starlark.String:
		name = string(e)
	case *object:
		if n, ok := e.attrs["name"].(starlark.String); ok {
			name = string(n)
		}
	}
	if name == "" {
		return nil, fmt.Errorf("ctx.derive_entry: entry must be a zip entry or a name")
	}
	v, err := r.host.View("zip")
	if err != nil {
		return nil, fmt.Errorf("ctx.derive_entry: %w", err)
	}
	z, ok := v.(*views.Zip)
	if !ok {
		return nil, fmt.Errorf("ctx.derive_entry: zip view has type %T", v)
	}
	entry, ok := z.Get(name)
	if !ok {
		return nil, fmt.Errorf("ctx.derive_entry: entry %q not found", name)
	}
	limit := r.lim.MaxDerivedBytes
	if limit <= 0 {
		limit = 512 << 20
	}
	data, err := entry.Read(limit + 1)
	if err != nil {
		return nil, fmt.Errorf("ctx.derive_entry: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("ctx.derive_entry: entry %q exceeds MaxDerivedBytes", name)
	}
	r.out.Derived = append(r.out.Derived, Derived{Name: name, Data: data, Speculative: speculative})
	return starlark.None, nil
}

// viewsValue exposes every registered view as ctx.view.<name>(). Views that
// implement views.Describer become read-only structs; the ZIP view also
// gets has/read/entries methods.
func (r *run) viewsValue() starlark.Value {
	attrs := map[string]starlark.Value{}
	for _, name := range views.Names() {
		attrs[name] = builtin("ctx.view."+name, func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackPositionalArgs("ctx.view."+name, args, kwargs, 0); err != nil {
				return nil, err
			}
			v, err := r.host.View(name)
			if err != nil {
				return nil, fmt.Errorf("ctx.view.%s: %w", name, err)
			}
			if z, ok := v.(*views.Zip); ok {
				return zipValue(z), nil
			}
			d, ok := v.(views.Describer)
			if !ok {
				return nil, fmt.Errorf("ctx.view.%s: view is not available to definitions", name)
			}
			return describedValue(name, d.Describe()), nil
		})
	}
	return newObject("view", attrs)
}

func describedValue(name string, md map[string]any) starlark.Value {
	attrs := make(map[string]starlark.Value, len(md))
	for k, v := range md {
		attrs[k] = fromGo(v)
	}
	return newObject(name, attrs)
}

func zipValue(z *views.Zip) starlark.Value {
	entry := func(e *views.ZipEntry) starlark.Value {
		return newObject("zip_entry", map[string]starlark.Value{
			"name":            starlark.String(e.Name),
			"is_dir":          starlark.Bool(e.IsDir),
			"size":            starlark.MakeInt64(e.Size),
			"compressed_size": starlark.MakeInt64(e.CompressedSize),
			"method":          starlark.MakeInt(int(e.Method)),
			"crc32":           starlark.MakeUint64(uint64(e.CRC32)),
			"encrypted":       starlark.Bool(e.Encrypted),
			"read": builtin("zip_entry.read", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				limit := e.Size
				if err := starlark.UnpackArgs("zip_entry.read", args, kwargs, "limit?", &limit); err != nil {
					return nil, err
				}
				b, err := e.Read(limit)
				return starlark.Bytes(string(b)), err
			}),
		})
	}
	attrs := map[string]starlark.Value{
		"has": builtin("zip.has", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var n string
			if err := starlark.UnpackPositionalArgs("zip.has", args, kwargs, 1, &n); err != nil {
				return nil, err
			}
			return starlark.Bool(z.Has(n)), nil
		}),
		"has_prefix": builtin("zip.has_prefix", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var n string
			if err := starlark.UnpackPositionalArgs("zip.has_prefix", args, kwargs, 1, &n); err != nil {
				return nil, err
			}
			return starlark.Bool(z.HasPrefix(n)), nil
		}),
		"read": builtin("zip.read", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var n string
			limit := int64(16 << 20)
			if err := starlark.UnpackArgs("zip.read", args, kwargs, "name", &n, "limit?", &limit); err != nil {
				return nil, err
			}
			b, err := z.Read(n, limit)
			return starlark.Bytes(string(b)), err
		}),
		"entries": builtin("zip.entries", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackPositionalArgs("zip.entries", args, kwargs, 0); err != nil {
				return nil, err
			}
			elems := make([]starlark.Value, len(z.Files))
			for i, f := range z.Files {
				elems[i] = entry(f)
			}
			return starlark.NewList(elems), nil
		}),
	}
	for k, v := range z.Describe() {
		attrs[k] = fromGo(v)
	}
	return newObject("zip", attrs)
}

func base64Module() starlark.Value {
	return newObject("base64", map[string]starlark.Value{
		"decode": builtin("base64.decode", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackPositionalArgs("base64.decode", args, kwargs, 1, &v); err != nil {
				return nil, err
			}
			b, err := toBytes(v)
			if err != nil {
				return nil, fmt.Errorf("base64.decode: %w", err)
			}
			s := strings.Join(strings.Fields(string(b)), "")
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if out, err := enc.DecodeString(s); err == nil {
					return starlark.Bytes(string(out)), nil
				}
			}
			return nil, fmt.Errorf("base64.decode: invalid base64")
		}),
		"encode": builtin("base64.encode", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackPositionalArgs("base64.encode", args, kwargs, 1, &v); err != nil {
				return nil, err
			}
			b, err := toBytes(v)
			if err != nil {
				return nil, fmt.Errorf("base64.encode: %w", err)
			}
			return starlark.String(base64.StdEncoding.EncodeToString(b)), nil
		}),
	})
}

func hexModule() starlark.Value {
	return newObject("hex", map[string]starlark.Value{
		"decode": builtin("hex.decode", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var s string
			if err := starlark.UnpackPositionalArgs("hex.decode", args, kwargs, 1, &s); err != nil {
				return nil, err
			}
			b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
			if err != nil {
				return nil, fmt.Errorf("hex.decode: %w", err)
			}
			return starlark.Bytes(string(b)), nil
		}),
		"encode": builtin("hex.encode", func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var v starlark.Value
			if err := starlark.UnpackPositionalArgs("hex.encode", args, kwargs, 1, &v); err != nil {
				return nil, err
			}
			b, err := toBytes(v)
			if err != nil {
				return nil, fmt.Errorf("hex.encode: %w", err)
			}
			return starlark.String(hex.EncodeToString(b)), nil
		}),
	})
}
