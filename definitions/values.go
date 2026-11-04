package definitions

import (
	stdjson "encoding/json"
	"fmt"
	"sort"

	"go.starlark.net/starlark"
)

// object is a read-only attribute bag exposed to Starlark.
type object struct {
	name  string
	attrs map[string]starlark.Value
}

func newObject(name string, attrs map[string]starlark.Value) *object {
	return &object{name: name, attrs: attrs}
}

func (o *object) String() string       { return "<" + o.name + ">" }
func (o *object) Type() string         { return o.name }
func (o *object) Truth() starlark.Bool { return starlark.True }
func (o *object) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: %s", o.name)
}
func (o *object) Freeze() {
	for _, v := range o.attrs {
		v.Freeze()
	}
}

// Attr implements starlark.HasAttrs. A missing attribute returns (nil, nil),
// which Starlark reports as "no such attribute".
func (o *object) Attr(n string) (starlark.Value, error) { return o.attrs[n], nil }

func (o *object) AttrNames() []string {
	names := make([]string, 0, len(o.attrs))
	for n := range o.attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

var (
	_ starlark.Value    = (*object)(nil)
	_ starlark.HasAttrs = (*object)(nil)
)

type builtinFn func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error)

func builtin(name string, fn builtinFn) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return fn(args, kwargs)
	})
}

func stringList(v starlark.Value) ([]string, error) {
	if v == nil || v == starlark.None {
		return nil, nil
	}
	if s, ok := v.(starlark.String); ok {
		return []string{string(s)}, nil
	}
	iter, ok := v.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("want a list of strings, got %s", v.Type())
	}
	it := iter.Iterate()
	defer it.Done()
	var out []string
	var x starlark.Value
	for it.Next(&x) {
		s, ok := x.(starlark.String)
		if !ok {
			return nil, fmt.Errorf("want a list of strings, found %s", x.Type())
		}
		out = append(out, string(s))
	}
	return out, nil
}

func toBytes(v starlark.Value) ([]byte, error) {
	switch t := v.(type) {
	case starlark.Bytes:
		return []byte(t), nil
	case starlark.String:
		return []byte(t), nil
	}
	return nil, fmt.Errorf("want bytes or string, got %s", v.Type())
}

// toGo converts a Starlark value to plain Go data for metadata.
func toGo(v starlark.Value) any {
	switch t := v.(type) {
	case nil, starlark.NoneType:
		return nil
	case starlark.Bool:
		return bool(t)
	case starlark.String:
		return string(t)
	case starlark.Bytes:
		return string(t)
	case starlark.Int:
		if n, ok := t.Int64(); ok {
			return n
		}
		return t.String()
	case starlark.Float:
		return float64(t)
	case *starlark.List:
		out := make([]any, t.Len())
		for i := range out {
			out[i] = toGo(t.Index(i))
		}
		return out
	case starlark.Tuple:
		out := make([]any, len(t))
		for i := range t {
			out[i] = toGo(t[i])
		}
		return out
	case *starlark.Dict:
		out := map[string]any{}
		for _, kv := range t.Items() {
			k, ok := kv[0].(starlark.String)
			key := string(k)
			if !ok {
				key = kv[0].String()
			}
			out[key] = toGo(kv[1])
		}
		return out
	}
	return v.String()
}

// fromGo converts plain Go data (JSON, described views) to Starlark.
func fromGo(v any) starlark.Value {
	switch t := v.(type) {
	case nil:
		return starlark.None
	case bool:
		return starlark.Bool(t)
	case string:
		return starlark.String(t)
	case []byte:
		return starlark.Bytes(string(t))
	case int:
		return starlark.MakeInt(t)
	case int64:
		return starlark.MakeInt64(t)
	case uint32:
		return starlark.MakeUint64(uint64(t))
	case uint64:
		return starlark.MakeUint64(t)
	case float64:
		return starlark.Float(t)
	case stdjson.Number:
		if n, err := t.Int64(); err == nil {
			return starlark.MakeInt64(n)
		}
		f, _ := t.Float64()
		return starlark.Float(f)
	case []string:
		elems := make([]starlark.Value, len(t))
		for i := range t {
			elems[i] = starlark.String(t[i])
		}
		return starlark.NewList(elems)
	case []any:
		elems := make([]starlark.Value, len(t))
		for i := range t {
			elems[i] = fromGo(t[i])
		}
		return starlark.NewList(elems)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		d := starlark.NewDict(len(keys))
		for _, k := range keys {
			_ = d.SetKey(starlark.String(k), fromGo(t[k]))
		}
		return d
	}
	return starlark.String(fmt.Sprint(v))
}

func kwargMap(kwargs []starlark.Tuple) map[string]starlark.Value {
	out := make(map[string]starlark.Value, len(kwargs))
	for _, kv := range kwargs {
		if k, ok := kv[0].(starlark.String); ok {
			out[string(k)] = kv[1]
		}
	}
	return out
}
