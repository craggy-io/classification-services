package classify

import (
	"fmt"
	"sort"
	"strings"
)

// Result is the outcome of classifying one piece of content. Children form
// a content DAG: equal digests share one *Result.
type Result struct {
	Digest  string  `json:"digest"` // SHA-256 of the content, hex
	Size    int64   `json:"size"`
	Name    string  `json:"name,omitempty"` // the source's name hint
	Primary string  `json:"primary"`        // most specific type, then highest evidence
	Matches []Match `json:"matches"`
	// Rejected lists refutations: a classifier showed the content is not
	// this type, removing weaker assertions of it.
	Rejected    []Rejection `json:"rejected,omitempty"`
	Anomalies   []Anomaly   `json:"anomalies,omitempty"`
	Children    []Child     `json:"children,omitempty"`
	Complete    bool        `json:"complete"`
	Limitations []string    `json:"limitations,omitempty"`
}

// Match is one established type, direct or inherited.
type Match struct {
	Type   string `json:"type"`
	Level  Level  `json:"level"`
	Direct bool   `json:"direct"`
	// Via lists, for an inherited match, the direct matches that imply it.
	Via      []string       `json:"via,omitempty"`
	By       []string       `json:"by,omitempty"` // classifiers that asserted it
	Metadata map[string]any `json:"metadata,omitempty"`
	// Evidence records each assertion behind a direct match.
	Evidence []Evidence `json:"evidence,omitempty"`
}

// Evidence is one assertion behind a match.
type Evidence struct {
	By     string `json:"by"`             // classifier ID, "signatures" or "engine"
	Kind   string `json:"kind"`           // "signature", "classifier" or "engine"
	Level  Level  `json:"level"`          // level this assertion claimed
	Rule   string `json:"rule,omitempty"` // signature rule ID
	Offset int64  `json:"offset,omitempty"`
	Length int64  `json:"length,omitempty"`
}

// Rejection is a refutation of a type.
type Rejection struct {
	Type  string `json:"type"`
	Level Level  `json:"level"` // assertions below this level were removed
	By    string `json:"by"`
	// Removed is set when the rejection removed at least one assertion.
	Removed bool `json:"removed,omitempty"`
}

// Child is derived content: an archive entry, a decompressed payload, an
// overlay, a speculative decoding.
type Child struct {
	Name        string `json:"name"`
	By          string `json:"by"` // deriving classifier
	Speculative bool   `json:"speculative,omitempty"`
	*Result     `json:"result"`
}

// Is reports whether t holds, directly or by inheritance.
func (r *Result) Is(t string) bool {
	_, ok := r.Get(t)
	return ok
}

// IsAtLeast reports whether t holds with evidence l or better.
func (r *Result) IsAtLeast(t string, l Level) bool {
	m, ok := r.Get(t)
	return ok && m.Level >= l
}

// Get returns the match for t.
func (r *Result) Get(t string) (Match, bool) {
	if r == nil {
		return Match{}, false
	}
	for _, m := range r.Matches {
		if m.Type == t {
			return m, true
		}
	}
	return Match{}, false
}

// Types returns every matched type, most specific first.
func (r *Result) Types() []string {
	if r == nil {
		return nil
	}
	out := make([]string, len(r.Matches))
	for i, m := range r.Matches {
		out[i] = m.Type
	}
	return out
}

// HasAnomaly reports whether an anomaly with code was reported for this
// node (not its children).
func (r *Result) HasAnomaly(code string) bool {
	if r == nil {
		return false
	}
	for _, a := range r.Anomalies {
		if a.Code == code {
			return true
		}
	}
	return false
}

// MaxSeverity returns the highest anomaly severity anywhere in the DAG,
// and whether any anomaly was reported.
func (r *Result) MaxSeverity() (Severity, bool) {
	var best Severity
	found := false
	_ = r.Walk(func(_ []string, n *Result) error {
		for _, a := range n.Anomalies {
			if !found || a.Severity > best {
				best, found = a.Severity, true
			}
		}
		return nil
	})
	return best, found
}

// AllLimitations lists the limitations of every node in the DAG, each
// prefixed with the node's derivation path ("a.zip/b.jar: ..."). Complete
// and Limitations describe one node; use this to see whether anything
// anywhere was cut short.
func (r *Result) AllLimitations() []string {
	var out []string
	_ = r.Walk(func(path []string, n *Result) error {
		for _, l := range n.Limitations {
			if len(path) == 0 {
				out = append(out, l)
			} else {
				out = append(out, strings.Join(path, "/")+": "+l)
			}
		}
		return nil
	})
	return out
}

// Walk visits every node once, depth-first, with its derivation path (the
// root's path is empty).
func (r *Result) Walk(fn func(path []string, n *Result) error) error {
	if r == nil || fn == nil {
		return nil
	}
	seen := map[*Result]bool{}
	var walk func([]string, *Result) error
	walk = func(path []string, n *Result) error {
		if n == nil || seen[n] {
			return nil
		}
		seen[n] = true
		if err := fn(append([]string(nil), path...), n); err != nil {
			return err
		}
		for _, c := range n.Children {
			if err := walk(append(path, c.Name), c.Result); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(nil, r)
}

// Explanation says why a type holds or was refuted.
type Explanation struct {
	Type       string      `json:"type"`
	Holds      bool        `json:"holds"`
	Level      Level       `json:"level,omitempty"`
	Direct     bool        `json:"direct,omitempty"`
	Via        []string    `json:"via,omitempty"`
	Evidence   []Evidence  `json:"evidence,omitempty"`
	Rejections []Rejection `json:"rejections,omitempty"`
	// Primary is set when Type is the result's primary type.
	Primary bool `json:"primary,omitempty"`
}

// Explain returns the evidence chain for t: the assertions behind a direct
// match, the direct matches an inherited one comes through (with their
// evidence), and any rejections of t. ok is false when t neither holds nor
// was rejected.
func (r *Result) Explain(t string) (Explanation, bool) {
	ex := Explanation{Type: t}
	if r == nil {
		return ex, false
	}
	for _, rj := range r.Rejected {
		if rj.Type == t {
			ex.Rejections = append(ex.Rejections, rj)
		}
	}
	m, holds := r.Get(t)
	if !holds {
		return ex, len(ex.Rejections) > 0
	}
	ex.Holds, ex.Level, ex.Direct, ex.Via, ex.Primary = true, m.Level, m.Direct, m.Via, r.Primary == t
	ex.Evidence = append(ex.Evidence, m.Evidence...)
	if !m.Direct {
		for _, v := range m.Via {
			if dm, ok := r.Get(v); ok {
				ex.Evidence = append(ex.Evidence, dm.Evidence...)
			}
		}
	}
	return ex, true
}

// String renders the explanation as indented lines.
func (ex Explanation) String() string {
	var b strings.Builder
	switch {
	case ex.Holds:
		kind := "inherited"
		if ex.Direct {
			kind = "direct"
		}
		fmt.Fprintf(&b, "%s holds (%s, %s)", ex.Type, ex.Level, kind)
		if ex.Primary {
			b.WriteString(", primary")
		}
		b.WriteByte('\n')
		if len(ex.Via) > 0 {
			fmt.Fprintf(&b, "  via %s\n", strings.Join(ex.Via, ", "))
		}
	default:
		fmt.Fprintf(&b, "%s does not hold\n", ex.Type)
	}
	for _, e := range ex.Evidence {
		switch e.Kind {
		case "signature":
			fmt.Fprintf(&b, "  %s: signature %s matched %d bytes at offset %d\n", e.Level, e.Rule, e.Length, e.Offset)
		default:
			fmt.Fprintf(&b, "  %s: asserted by %s %s\n", e.Level, e.Kind, e.By)
		}
	}
	for _, rj := range ex.Rejections {
		verb := "refuted"
		if rj.Removed {
			verb = "refuted, removing weaker assertions"
		}
		fmt.Fprintf(&b, "  rejected by %s at %s (%s)\n", rj.By, rj.Level, verb)
	}
	return b.String()
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
