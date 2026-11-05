package classify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/craggy-io/foundation-kit/bundle"

	"github.com/craggy-io/classification-services/catalog"
	"github.com/craggy-io/classification-services/definitions"
	"github.com/craggy-io/classification-services/signatures"
	"github.com/craggy-io/classification-services/views"
)

// entry is one classifier in a snapshot: native or Starlark.
type entry struct {
	spec   Spec
	rev    string // cache revision: identity plus the types it reads
	module string // defining module, or "native"
	native Classifier
	star   *definitions.Classifier
}

func (ce *entry) run(ctx context.Context, in *Input, lim Limits) (Output, error) {
	if ce.native != nil {
		return ce.native.Classify(ctx, in)
	}
	out, err := ce.star.Run(ctx, starHost{in}, definitions.Limits{Steps: lim.ScriptSteps, MaxDerivedBytes: lim.MaxDerivedBytes})
	if err != nil {
		return Output{}, err
	}
	res := Output{Anomalies: out.Anomalies}
	for _, a := range out.Assertions {
		res.Assertions = append(res.Assertions, Assertion{Type: a.Type, Level: a.Level, Metadata: a.Metadata, Reject: a.Reject})
	}
	for _, d := range out.Derived {
		res.Derived = append(res.Derived, Derived{Name: d.Name, Data: d.Data, Offset: d.Offset, Length: d.Length, Speculative: d.Speculative})
	}
	return res, nil
}

// starHost adapts Input to the definitions host contract.
type starHost struct{ in *Input }

func (h starHost) Size() int64                            { return h.in.Size() }
func (h starHost) Digest() string                         { return h.in.Digest() }
func (h starHost) Name() string                           { return h.in.Name() }
func (h starHost) ReadRange(off, n int64) ([]byte, error) { return h.in.Read(off, n) }
func (h starHost) JSON(limit int64) (any, error)          { return h.in.JSON(limit) }
func (h starHost) View(name string) (any, error)          { return h.in.View(name) }
func (h starHost) Facet(t string) (map[string]any, bool) {
	m, ok := h.in.Facet(t)
	return m.Metadata, ok
}

var _ definitions.Host = starHost{}

// snapshot is an immutable, validated view of catalogue, classifiers and
// signatures. Every Classify captures one at entry, so Define and Remove
// never affect a call in flight.
type snapshot struct {
	catalog     *catalog.Catalog
	classifiers []*entry
	byID        map[string]*entry
	waiting     map[string][]int // type -> indexes of classifiers requiring it
	matcher     *signatures.Matcher
	revision    string
	modules     map[string]*definitions.Module // effective modules by name
	owners      map[string]string              // module name -> owning bundle ID
	tests       map[string][]definitions.Test
	bundles     *bundle.Catalog // the definitions catalog this was built from
}

// newSnapshot builds a snapshot from a definitions catalog: every effective
// module and CyberChef set in it, plus the native classifiers.
func newSnapshot(cat *bundle.Catalog, natives []Classifier) (*snapshot, error) {
	modules := map[string]*definitions.Module{}
	owners := map[string]string{}
	for _, d := range bundle.All(cat, definitions.ModuleKind) {
		modules[d.Value.Name] = d.Value
		owners[d.Value.Name] = d.Owner.ID
	}
	var sigs []signatures.Rule
	for _, d := range bundle.All(cat, signatures.CyberChefKind) {
		sigs = append(sigs, d.Value...)
	}
	snap, err := buildSnapshot(modules, natives, sigs)
	if err != nil {
		return nil, err
	}
	snap.owners, snap.bundles = owners, cat
	return snap, nil
}

// intrinsicTypes are the roots the engine asserts itself.
func intrinsicTypes() []TypeInfo {
	return []TypeInfo{
		{Name: catalog.Bytes, MIME: "application/octet-stream", Description: "Any content", Abstract: true},
		{Name: catalog.Text, Parents: []string{catalog.Bytes}, MIME: "text/plain", Ext: []string{"txt", "text", "log"}, Description: "UTF-8 text"},
	}
}

func buildSnapshot(modules map[string]*definitions.Module, natives []Classifier, extra []signatures.Rule) (*snapshot, error) {
	names := make([]string, 0, len(modules))
	for n := range modules {
		names = append(names, n)
	}
	sort.Strings(names)

	infos := intrinsicTypes()
	for _, n := range names {
		infos = append(infos, modules[n].Types...)
	}
	for _, nc := range natives {
		infos = append(infos, nc.Spec().Types...)
	}
	cat, err := catalog.Build(infos)
	if err != nil {
		return nil, err
	}
	snap := &snapshot{catalog: cat, byID: map[string]*entry{}, waiting: map[string][]int{}, modules: modules, tests: map[string][]definitions.Test{}}

	add := func(ce *entry, identity string) error {
		id := ce.spec.ID
		if id == "" {
			return fmt.Errorf("classify: a classifier from %s has an empty ID", ce.module)
		}
		if prev, dup := snap.byID[id]; dup {
			return fmt.Errorf("classify: duplicate classifier ID %q (from %s and %s)", id, prev.module, ce.module)
		}
		if len(ce.spec.Requires) == 0 {
			ce.spec.Requires = []string{catalog.Bytes}
		}
		for _, t := range ce.spec.Produces {
			if !cat.Has(t) {
				return fmt.Errorf("classify: classifier %q produces unknown type %q", id, t)
			}
		}
		for _, t := range ce.spec.Requires {
			if !cat.Has(t) {
				return fmt.Errorf("classify: classifier %q requires unknown type %q", id, t)
			}
		}
		ce.rev = classifierRevision(cat, ce.spec, identity)
		snap.byID[id] = ce
		snap.classifiers = append(snap.classifiers, ce)
		return nil
	}
	var rules []signatures.Rule
	rules = append(rules, extra...)
	for _, n := range names {
		m := modules[n]
		for _, c := range m.Classifiers {
			ce := &entry{spec: Spec{ID: c.ID, Produces: c.Produces, Requires: c.Requires, Derives: c.Derives}, module: n, star: c}
			if err := add(ce, "star:"+m.SourceHash); err != nil {
				return nil, err
			}
		}
		rules = append(rules, m.Signatures...)
		if len(m.Tests) > 0 {
			snap.tests[n] = m.Tests
		}
	}
	for _, nc := range natives {
		s := nc.Spec()
		if err := add(&entry{spec: s, module: "native", native: nc}, "native:"+s.Revision); err != nil {
			return nil, err
		}
	}
	sort.Slice(snap.classifiers, func(i, j int) bool { return snap.classifiers[i].spec.ID < snap.classifiers[j].spec.ID })
	for i, ce := range snap.classifiers {
		for _, r := range ce.spec.Requires {
			snap.waiting[r] = append(snap.waiting[r], i)
		}
	}
	for _, r := range rules {
		if !cat.Has(r.Type) {
			return nil, fmt.Errorf("classify: signature %q references unknown type %q", r.ID, r.Type)
		}
	}
	if snap.matcher, err = signatures.New(rules); err != nil {
		return nil, err
	}

	h := sha256.New()
	fmt.Fprintf(h, "catalog %s\n", cat.Revision())
	for _, ce := range snap.classifiers {
		fmt.Fprintf(h, "classifier %s %s\n", ce.spec.ID, ce.rev)
	}
	for _, r := range snap.matcher.Rules() {
		fmt.Fprintln(h, "sig", r.Canonical())
	}
	snap.revision = hex.EncodeToString(h.Sum(nil))[:16]
	return snap, nil
}

// classifierRevision hashes a classifier's identity and the definitions of
// the types in Produces/Requires, so an unrelated Define does not rerun
// native classifiers (whose facet reads are covered by their Spec
// Revision). Starlark classifiers may read facets of arbitrary types
// (ctx.has/ctx.facet) and any registered view (ctx.view.*), so their
// revision also covers the whole catalogue and the views revision.
func classifierRevision(cat *catalog.Catalog, s Spec, identity string) string {
	h := sha256.New()
	produces, requires := slices.Clone(s.Produces), slices.Clone(s.Requires)
	sort.Strings(produces)
	sort.Strings(requires)
	fmt.Fprintf(h, "id %s\nidentity %s\nproduces %s\nrequires %s\nderives %t\n",
		s.ID, identity, strings.Join(produces, ","), strings.Join(requires, ","), s.Derives)
	if strings.HasPrefix(identity, "star:") {
		fmt.Fprintf(h, "catalog %s\nviews %s\n", cat.Revision(), views.Revision)
	}
	reads := append(produces, requires...)
	sort.Strings(reads)
	for _, t := range reads {
		fmt.Fprintf(h, "type %s %s\n", t, cat.TypeRevision(t))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// entryNames lists every cache entry name the snapshot can produce, for
// maintenance.
func (s *snapshot) entryNames() map[string]bool {
	keep := map[string]bool{}
	for _, ce := range s.classifiers {
		keep[classifierFileName(ce)] = true
	}
	for _, d := range []Depth{Quick, Standard, Deep} {
		for _, text := range []bool{false, true} {
			keep[nodeFileName(s.revision, d, text)] = true
		}
	}
	return keep
}
