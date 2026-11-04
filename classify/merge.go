package classify

import (
	"slices"
	"sort"

	"github.com/craggy-io/classification-services/catalog"
)

// raw is one assertion with its provenance.
type raw struct {
	a  Assertion
	ev Evidence
}

// merge folds raw assertions into a Result's matches: rejections remove
// weaker assertions of their type, assertions of the same type merge
// (highest level wins and supplies the metadata), inheritance expands the
// type DAG, and the primary is chosen.
func merge(cat *catalog.Catalog, digest string, size int64, raws []raw) *Result {
	rejectAt := map[string]Level{}
	rejectBy := map[string][]string{}
	for _, r := range raws {
		if !r.a.Reject {
			continue
		}
		l := r.a.Level
		if l == 0 {
			l = Validated
		}
		rejectAt[r.a.Type] = max(rejectAt[r.a.Type], l)
		rejectBy[r.a.Type] = append(rejectBy[r.a.Type], r.ev.By)
	}
	removed := map[string]bool{}
	groups := map[string][]raw{}
	for _, r := range raws {
		if r.a.Reject || r.a.Type == "" {
			continue
		}
		if r.a.Level == 0 {
			r.a.Level = Recognised
			r.ev.Level = Recognised
		}
		if rl, ok := rejectAt[r.a.Type]; ok && r.a.Level < rl {
			removed[r.a.Type] = true
			continue
		}
		groups[r.a.Type] = append(groups[r.a.Type], r)
	}

	res := &Result{Digest: digest, Size: size, Complete: true}
	for t, l := range rejectAt {
		for _, by := range sortedUnique(rejectBy[t]) {
			res.Rejected = append(res.Rejected, Rejection{Type: t, Level: l, By: by, Removed: removed[t]})
		}
	}
	sort.Slice(res.Rejected, func(i, j int) bool {
		if res.Rejected[i].Type != res.Rejected[j].Type {
			return res.Rejected[i].Type < res.Rejected[j].Type
		}
		return res.Rejected[i].By < res.Rejected[j].By
	})

	matches := map[string]*Match{}
	for t, g := range groups {
		sort.SliceStable(g, func(i, j int) bool {
			if g[i].a.Level != g[j].a.Level {
				return g[i].a.Level > g[j].a.Level
			}
			return g[i].ev.By < g[j].ev.By
		})
		m := &Match{Type: t, Direct: true, Level: g[0].a.Level, Metadata: sanitizeMetadata(g[0].a.Metadata)}
		var by []string
		for _, r := range g {
			by = append(by, r.ev.By)
			m.Evidence = append(m.Evidence, r.ev)
		}
		m.By = sortedUnique(by)
		sort.SliceStable(m.Evidence, func(i, j int) bool {
			if m.Evidence[i].Level != m.Evidence[j].Level {
				return m.Evidence[i].Level > m.Evidence[j].Level
			}
			return m.Evidence[i].By < m.Evidence[j].By
		})
		matches[t] = m
	}
	direct := make([]string, 0, len(matches))
	for t := range matches {
		direct = append(direct, t)
	}
	sort.Strings(direct)
	for _, t := range direct {
		m := matches[t]
		for _, anc := range cat.Ancestors(t) {
			im, ok := matches[anc]
			if !ok {
				im = &Match{Type: anc}
				matches[anc] = im
			}
			im.Level = max(im.Level, m.Level)
			if !im.Direct {
				im.Via = append(im.Via, t)
				im.By = append(im.By, m.By...)
			}
		}
	}
	for _, m := range matches {
		if !m.Direct {
			m.Via = sortedUnique(m.Via)
			m.By = sortedUnique(m.By)
		}
		res.Matches = append(res.Matches, *m)
	}
	sort.Slice(res.Matches, func(i, j int) bool {
		a, b := res.Matches[i], res.Matches[j]
		if da, db := cat.Depth(a.Type), cat.Depth(b.Type); da != db {
			return da > db
		}
		if a.Level != b.Level {
			return a.Level > b.Level
		}
		return a.Type < b.Type
	})
	res.Primary = pickPrimary(cat, res.Matches)
	return res
}

// pickPrimary chooses among matches with no matched descendant (the most
// specific), preferring concrete types, then higher evidence, declared
// priority, depth and name.
func pickPrimary(cat *catalog.Catalog, matches []Match) string {
	if len(matches) == 0 {
		return ""
	}
	matched := make(map[string]bool, len(matches))
	for _, m := range matches {
		matched[m.Type] = true
	}
	var best *Match
	var bestInfo TypeInfo
	for i := range matches {
		m := &matches[i]
		leaf := true
		for other := range matched {
			if other != m.Type && cat.IsA(other, m.Type) {
				leaf = false
				break
			}
		}
		if !leaf {
			continue
		}
		info, _ := cat.Get(m.Type)
		if best == nil || primaryBefore(cat, *m, info, *best, bestInfo) {
			best, bestInfo = m, info
		}
	}
	if best == nil {
		return matches[0].Type
	}
	return best.Type
}

func primaryBefore(cat *catalog.Catalog, a Match, ai TypeInfo, b Match, bi TypeInfo) bool {
	if ai.Abstract != bi.Abstract {
		return !ai.Abstract
	}
	if a.Level != b.Level {
		return a.Level > b.Level
	}
	// A format whose signature sits at offset 0 is the outer one: an ELF
	// with a ZIP appended is primarily an ELF.
	if a0, b0 := atStart(a), atStart(b); a0 != b0 {
		return a0
	}
	if ai.Priority != bi.Priority {
		return ai.Priority > bi.Priority
	}
	if da, db := cat.Depth(a.Type), cat.Depth(b.Type); da != db {
		return da > db
	}
	return a.Type < b.Type
}

func atStart(m Match) bool {
	for _, e := range m.Evidence {
		if e.Kind == "signature" && e.Offset == 0 {
			return true
		}
	}
	return false
}

// matchIndex maps every match (direct and inherited) by type.
func matchIndex(ms []Match) map[string]Match {
	out := make(map[string]Match, len(ms))
	for _, m := range ms {
		out[m.Type] = m
	}
	return out
}

func appendAnomalies(dst []Anomaly, src ...Anomaly) []Anomaly {
	for _, a := range src {
		dup := slices.ContainsFunc(dst, func(b Anomaly) bool { return a.Code == b.Code && a.By == b.By && a.Message == b.Message })
		if !dup && a.Code != "" {
			a.Metadata = sanitizeMetadata(a.Metadata)
			dst = append(dst, a)
		}
	}
	return dst
}

func sortAnomalies(as []Anomaly) {
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Severity != as[j].Severity {
			return as[i].Severity > as[j].Severity
		}
		if as[i].Code != as[j].Code {
			return as[i].Code < as[j].Code
		}
		return as[i].By < as[j].By
	})
}
