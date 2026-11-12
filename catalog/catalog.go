// Package catalog is the classifier's view of the type graph: the shared
// taxonomy from foundation-kit, plus the file-format facts only this library
// knows about a type (MIME type, extensions, priority). A Catalog is
// immutable once built and safe for concurrent use.
//
// Names, parents, IsA and the graph's rules are foundation-kit's taxonomy
// package. This package adds the rules that are specific to file contents:
// "bytes" is the root every type here descends from, and a single-label name
// other than "bytes" and "text" is an abstract namespace.
//
// Build makes a catalog of this library's types alone. BuildIn builds one
// over a host's live taxonomy, so the graph also holds the types other owners
// declared and these types may descend from them.
package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/craggy-io/foundation-kit/taxonomy"
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

// node is t as the shared taxonomy sees it: the name and relationships,
// without the file-format facts.
func (t TypeInfo) node() taxonomy.Type {
	return taxonomy.Type{Name: t.Name, Parents: slices.Clone(t.Parents), Description: t.Description, Abstract: t.Abstract}
}

// Namespace returns the part of name before the first dot, or "" for a
// root-level name.
func Namespace(name string) string { return taxonomy.Namespace(name) }

// Catalog is a validated type graph with each type's file-format facts.
type Catalog struct {
	tax      *taxonomy.Taxonomy
	own      []TypeInfo          // the types this catalog was built from
	types    map[string]TypeInfo // every type in tax
	byExt    map[string][]string
	revision string
}

// privateOwner owns the types of a catalog that shares no live taxonomy.
const privateOwner = "catalog"

// Build validates infos into a catalog that holds only those types.
// Identical redeclarations are tolerated (two modules may share a type);
// conflicting ones are errors.
func Build(infos []TypeInfo) (*Catalog, error) {
	return build(infos, func(own []taxonomy.Type) (*taxonomy.Taxonomy, error) {
		return taxonomy.New(taxonomy.Set{Owner: privateOwner, Types: own})
	})
}

// BuildIn validates infos as owner's types in a host's live taxonomy. The
// catalog's graph is what live would hold once owner declared them, so it
// includes other owners' types, and infos may descend from those. Nothing is
// published: call live.Declare(owner, c.Own()) to do that.
func BuildIn(live *taxonomy.Live, owner string, infos []TypeInfo) (*Catalog, error) {
	return build(infos, func(own []taxonomy.Type) (*taxonomy.Taxonomy, error) {
		return live.Preview(owner, own)
	})
}

func build(infos []TypeInfo, graph func([]taxonomy.Type) (*taxonomy.Taxonomy, error)) (*Catalog, error) {
	c := &Catalog{types: map[string]TypeInfo{}, byExt: map[string][]string{}}
	for _, ti := range infos {
		ti = ti.Normalize()
		if ti.Name == "" {
			return nil, fmt.Errorf("catalog: type with empty name")
		}
		if !taxonomy.ValidName(ti.Name) {
			return nil, fmt.Errorf("catalog: invalid type name %q (want lower-case namespace.name)", ti.Name)
		}
		if !strings.Contains(ti.Name, ".") && !ti.Abstract && ti.Name != Bytes && ti.Name != Text {
			return nil, fmt.Errorf("catalog: concrete type %q must be namespace.name (single labels are abstract namespaces)", ti.Name)
		}
		if ti.Name != Bytes && len(ti.Parents) == 0 {
			return nil, fmt.Errorf("catalog: type %q has no parents (every type except %q descends from it)", ti.Name, Bytes)
		}
		if prev, ok := c.types[ti.Name]; ok {
			if prev.fingerprint() != ti.fingerprint() {
				return nil, fmt.Errorf("catalog: type %q redeclared differently", ti.Name)
			}
			continue
		}
		c.types[ti.Name] = ti
		c.own = append(c.own, ti)
	}
	tax, err := graph(c.Own())
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	c.tax = tax
	h := sha256.New()
	for _, t := range tax.Types() {
		ti, ok := c.types[t.Name]
		if !ok {
			// Another owner's type: it has no file-format facts.
			ti = TypeInfo{Name: t.Name, Parents: t.Parents, Description: t.Description, Abstract: t.Abstract}
			c.types[t.Name] = ti
		}
		for _, e := range ti.Ext {
			c.byExt[e] = append(c.byExt[e], t.Name)
		}
		fmt.Fprintln(h, ti.fingerprint())
	}
	c.revision = hex.EncodeToString(h.Sum(nil))[:16]
	return c, nil
}

// Taxonomy returns the shared graph this catalog reads.
func (c *Catalog) Taxonomy() *taxonomy.Taxonomy { return c.tax }

// Own returns the types this catalog was built from, as the taxonomy sees
// them: what its owner declares in a live taxonomy.
func (c *Catalog) Own() []taxonomy.Type {
	out := make([]taxonomy.Type, len(c.own))
	for i, ti := range c.own {
		out[i] = ti.node()
	}
	return out
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
func (c *Catalog) Has(name string) bool { return c.tax.Has(name) }

// Get returns a copy of the type's definition.
func (c *Catalog) Get(name string) (TypeInfo, bool) {
	ti, ok := c.types[name]
	return ti.clone(), ok
}

// IsA reports whether child is parent or one of its descendants. An
// undeclared type is not anything, not even itself.
func (c *Catalog) IsA(child, parent string) bool { return c.tax.IsA(child, parent) }

// Ancestors returns name's ancestors (excluding name), sorted.
func (c *Catalog) Ancestors(name string) []string { return c.tax.Ancestors(name) }

// Depth is the length of the longest parent path from name to a root.
// Deeper types are more specific.
func (c *Catalog) Depth(name string) int { return c.tax.Depth(name) }

// Closure returns the given types plus all their ancestors.
func (c *Catalog) Closure(types map[string]bool) map[string]bool { return c.tax.Closure(types) }

// ByExtension returns the types declaring ext (without dot), sorted.
func (c *Catalog) ByExtension(ext string) []string {
	ext = strings.TrimPrefix(strings.ToLower(ext), ".")
	out := slices.Clone(c.byExt[ext])
	sort.Strings(out)
	return out
}

// Types returns every type, sorted by name.
func (c *Catalog) Types() []TypeInfo {
	nodes := c.tax.Types()
	out := make([]TypeInfo, len(nodes))
	for i, t := range nodes {
		out[i] = c.types[t.Name].clone()
	}
	return out
}

// Len returns the number of types.
func (c *Catalog) Len() int { return c.tax.Len() }
