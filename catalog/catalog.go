// Package catalog is the type DAG: every type declares its parents, ancestor
// sets are precomputed, and IsA is a map lookup. A Catalog is immutable once
// built and safe for concurrent use.
//
// Type names are "namespace.name" (for example "archive.zip",
// "executable.elf"), plus the two roots "bytes" and "text". When a type's
// namespace ("archive") is itself a declared type, the type must descend from
// it, so namespace membership and IsA never disagree.
package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Root types asserted by the engine itself.
const (
	Bytes = "bytes" // every input
	Text  = "text"  // UTF-8 text; asserted for Text sources or by the text probe
)

// TypeInfo describes one type.
type TypeInfo struct {
	Name        string   `json:"name"`
	Parents     []string `json:"parents,omitempty"`
	MIME        string   `json:"mime,omitempty"`
	Ext         []string `json:"ext,omitempty"` // lower-case, without the leading dot
	Priority    int      `json:"priority,omitempty"`
	Description string   `json:"description,omitempty"`
	// Abstract types group others (namespaces such as "archive"). They can
	// be required by classifiers but are never chosen as a primary when a
	// concrete descendant holds.
	Abstract bool `json:"abstract,omitempty"`
}

// Normalize trims names and extensions, lower-cases extensions and removes
// duplicate or self-referential parents.
func (t TypeInfo) Normalize() TypeInfo {
	t.Name = strings.TrimSpace(t.Name)
	t.MIME = strings.TrimSpace(t.MIME)
	var parents []string
	for _, p := range t.Parents {
		p = strings.TrimSpace(p)
		if p != "" && p != t.Name && !slices.Contains(parents, p) {
			parents = append(parents, p)
		}
	}
	sort.Strings(parents)
	t.Parents = parents
	var ext []string
	for _, e := range t.Ext {
		e = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), ".")
		if e != "" && !slices.Contains(ext, e) {
			ext = append(ext, e)
		}
	}
	sort.Strings(ext)
	t.Ext = ext
	return t
}

func (t TypeInfo) clone() TypeInfo {
	t.Parents = slices.Clone(t.Parents)
	t.Ext = slices.Clone(t.Ext)
	return t
}

func (t TypeInfo) fingerprint() string {
	// Length-prefix every variable field so different definitions cannot
	// collide through delimiter-bearing values (Ext ["p,q"] vs ["p","q"]).
	field := func(s string) string { return fmt.Sprintf("%d:%s", len(s), s) }
	var b strings.Builder
	for _, s := range []string{t.Name, t.MIME, t.Description} {
		b.WriteString(field(s))
		b.WriteByte('|')
	}
	fmt.Fprintf(&b, "parents%d|", len(t.Parents))
	for _, s := range t.Parents {
		b.WriteString(field(s))
		b.WriteByte('|')
	}
	fmt.Fprintf(&b, "ext%d|", len(t.Ext))
	for _, s := range t.Ext {
		b.WriteString(field(s))
		b.WriteByte('|')
	}
	fmt.Fprintf(&b, "%d|%t", t.Priority, t.Abstract)
	return b.String()
}

// Namespace returns the part of name before the first dot, or "" for a
// root-level name.
func Namespace(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return ""
}

// Catalog is a validated type DAG.
type Catalog struct {
	types     map[string]TypeInfo
	ancestors map[string]map[string]bool // excludes self
	depth     map[string]int             // longest path to a root
	byExt     map[string][]string
	revision  string
}

// Build validates infos into a catalog. Identical redeclarations are
// tolerated (two modules may share a type); conflicting ones are errors.
func Build(infos []TypeInfo) (*Catalog, error) {
	c := &Catalog{
		types:     map[string]TypeInfo{},
		ancestors: map[string]map[string]bool{},
		depth:     map[string]int{},
		byExt:     map[string][]string{},
	}
	for _, ti := range infos {
		ti = ti.Normalize()
		if ti.Name == "" {
			return nil, fmt.Errorf("catalog: type with empty name")
		}
		if !validName(ti.Name) {
			return nil, fmt.Errorf("catalog: invalid type name %q (want lower-case namespace.name)", ti.Name)
		}
		if !strings.Contains(ti.Name, ".") && !ti.Abstract && ti.Name != Bytes && ti.Name != Text {
			return nil, fmt.Errorf("catalog: concrete type %q must be namespace.name (single labels are abstract namespaces)", ti.Name)
		}
		if prev, ok := c.types[ti.Name]; ok {
			if prev.fingerprint() != ti.fingerprint() {
				return nil, fmt.Errorf("catalog: type %q redeclared differently", ti.Name)
			}
			continue
		}
		c.types[ti.Name] = ti
	}
	for name, ti := range c.types {
		if name != Bytes && len(ti.Parents) == 0 {
			return nil, fmt.Errorf("catalog: type %q has no parents (every type except %q descends from it)", name, Bytes)
		}
		for _, p := range ti.Parents {
			if _, ok := c.types[p]; !ok {
				return nil, fmt.Errorf("catalog: type %q has unknown parent %q", name, p)
			}
		}
	}
	const (
		white = iota
		grey
		black
	)
	colour := map[string]int{}
	var visit func(string) error
	visit = func(name string) error {
		switch colour[name] {
		case grey:
			return fmt.Errorf("catalog: cycle in type DAG at %q", name)
		case black:
			return nil
		}
		colour[name] = grey
		anc := map[string]bool{}
		depth := 0
		for _, p := range c.types[name].Parents {
			if err := visit(p); err != nil {
				return err
			}
			anc[p] = true
			for a := range c.ancestors[p] {
				anc[a] = true
			}
			depth = max(depth, c.depth[p]+1)
		}
		c.ancestors[name] = anc
		c.depth[name] = depth
		colour[name] = black
		return nil
	}
	names := c.sortedNames()
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	for _, name := range names {
		ns := Namespace(name)
		if _, declared := c.types[ns]; declared && !c.ancestors[name][ns] {
			return nil, fmt.Errorf("catalog: type %q is in namespace %q but does not descend from it", name, ns)
		}
		for _, e := range c.types[name].Ext {
			c.byExt[e] = append(c.byExt[e], name)
		}
	}
	h := sha256.New()
	for _, name := range names {
		fmt.Fprintln(h, c.types[name].fingerprint())
	}
	c.revision = hex.EncodeToString(h.Sum(nil))[:16]
	return c, nil
}

func validName(s string) bool {
	if s == "" || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == '+':
		default:
			return false
		}
	}
	return true
}

func (c *Catalog) sortedNames() []string {
	names := make([]string, 0, len(c.types))
	for n := range c.types {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Revision identifies the whole catalogue's content.
func (c *Catalog) Revision() string { return c.revision }

// TypeRevision identifies one type's definition (used in classifier cache
// keys, so editing a type a classifier reads invalidates its results).
func (c *Catalog) TypeRevision(name string) string {
	ti, ok := c.types[name]
	if !ok {
		return "missing:" + name
	}
	sum := sha256.Sum256([]byte(ti.fingerprint()))
	return hex.EncodeToString(sum[:8])
}

// Has reports whether name is a declared type.
func (c *Catalog) Has(name string) bool {
	_, ok := c.types[name]
	return ok
}

// Get returns a copy of the type's definition.
func (c *Catalog) Get(name string) (TypeInfo, bool) {
	ti, ok := c.types[name]
	return ti.clone(), ok
}

// IsA reports whether child is parent or one of its descendants. An
// undeclared type is not anything, not even itself.
func (c *Catalog) IsA(child, parent string) bool {
	if child == parent {
		return c.Has(child)
	}
	return c.ancestors[child][parent]
}

// Ancestors returns name's ancestors (excluding name), sorted.
func (c *Catalog) Ancestors(name string) []string {
	out := make([]string, 0, len(c.ancestors[name]))
	for a := range c.ancestors[name] {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Depth is the length of the longest parent path from name to the root.
// Deeper types are more specific.
func (c *Catalog) Depth(name string) int { return c.depth[name] }

// Closure returns the given types plus all their ancestors.
func (c *Catalog) Closure(types map[string]bool) map[string]bool {
	out := make(map[string]bool, len(types)*2)
	for t := range types {
		out[t] = true
		for a := range c.ancestors[t] {
			out[a] = true
		}
	}
	return out
}

// ByExtension returns the types declaring ext (without dot), sorted.
func (c *Catalog) ByExtension(ext string) []string {
	ext = strings.TrimPrefix(strings.ToLower(ext), ".")
	out := slices.Clone(c.byExt[ext])
	sort.Strings(out)
	return out
}

// Types returns every type, sorted by name.
func (c *Catalog) Types() []TypeInfo {
	names := c.sortedNames()
	out := make([]TypeInfo, len(names))
	for i, n := range names {
		out[i] = c.types[n].clone()
	}
	return out
}

// Len returns the number of types.
func (c *Catalog) Len() int { return len(c.types) }
