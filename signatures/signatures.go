// Package signatures is the compiled byte-signature matcher. Rules are sets
// of fixed-offset patterns; each position is a 256-bit byte set, which covers
// literal bytes, wildcards and the CyberChef predicates (equal, one_of,
// not_equal, range) uniformly. Rules are bucketed by (offset, first concrete
// byte) so a prefix is checked against only the rules that could match.
//
// Signatures only ever produce candidate (or explicitly declared) evidence;
// structural validators raise or refute them.
package signatures

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/craggy-io/classification-services/evidence"
)

// ByteSet is the set of byte values allowed at one pattern position.
type ByteSet [4]uint64

// Any returns the wildcard set.
func Any() ByteSet { return ByteSet{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)} }

// Only returns the set holding just v.
func Only(v byte) ByteSet {
	var s ByteSet
	return s.Add(v)
}

// Add returns s with v added.
func (s ByteSet) Add(v byte) ByteSet {
	s[v/64] |= 1 << (v % 64)
	return s
}

// Remove returns s with v removed.
func (s ByteSet) Remove(v byte) ByteSet {
	s[v/64] &^= 1 << (v % 64)
	return s
}

// Intersect returns the bytes allowed by both sets.
func (s ByteSet) Intersect(o ByteSet) ByteSet {
	for i := range s {
		s[i] &= o[i]
	}
	return s
}

// Contains reports whether v is allowed.
func (s ByteSet) Contains(v byte) bool { return s[v/64]&(1<<(v%64)) != 0 }

// IsAny reports whether every byte is allowed.
func (s ByteSet) IsAny() bool { return s == Any() }

// Single returns the only allowed byte, if exactly one is.
func (s ByteSet) Single() (byte, bool) {
	found := -1
	for i := 0; i < 256; i++ {
		if s.Contains(byte(i)) {
			if found >= 0 {
				return 0, false
			}
			found = i
		}
	}
	return byte(found), found >= 0
}

func (s ByteSet) String() string {
	if s.IsAny() {
		return "??"
	}
	if v, ok := s.Single(); ok {
		return fmt.Sprintf("%02x", v)
	}
	var vals []string
	for i := 0; i < 256; i++ {
		if s.Contains(byte(i)) {
			vals = append(vals, fmt.Sprintf("%02x", i))
		}
	}
	return "{" + strings.Join(vals, ",") + "}"
}

// Pattern is one contiguous run of position sets at a fixed offset.
type Pattern struct {
	Offset int64
	Sets   []ByteSet
}

// End is the offset just past the pattern.
func (p Pattern) End() int64 { return p.Offset + int64(len(p.Sets)) }

// Canonical is a stable textual form used in revision hashes.
func (p Pattern) Canonical() string {
	var b strings.Builder
	fmt.Fprintf(&b, "@%d:", p.Offset)
	for _, s := range p.Sets {
		b.WriteString(s.String())
	}
	return b.String()
}

// Literal builds a pattern of exact bytes.
func Literal(offset int64, raw []byte) Pattern {
	sets := make([]ByteSet, len(raw))
	for i, b := range raw {
		sets[i] = Only(b)
	}
	return Pattern{Offset: offset, Sets: sets}
}

// Hex parses hex with optional spaces and "??" wildcards ("50 4b ?? 04").
func Hex(offset int64, s string) (Pattern, error) {
	if offset < 0 {
		return Pattern{}, fmt.Errorf("signatures: negative offset %d", offset)
	}
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if s == "" {
		return Pattern{}, fmt.Errorf("signatures: empty pattern")
	}
	if len(s)%2 != 0 {
		return Pattern{}, fmt.Errorf("signatures: pattern %q has odd length", s)
	}
	sets := make([]ByteSet, len(s)/2)
	for i := range sets {
		pair := s[2*i : 2*i+2]
		if pair == "??" {
			sets[i] = Any()
			continue
		}
		v, err := hex.DecodeString(pair)
		if err != nil {
			return Pattern{}, fmt.Errorf("signatures: pattern %q: invalid byte %q", s, pair)
		}
		sets[i] = Only(v[0])
	}
	return Pattern{Offset: offset, Sets: sets}, nil
}

func (p Pattern) firstConcrete() (int64, int) {
	for i, s := range p.Sets {
		if s.IsAny() {
			continue
		}
		if v, ok := s.Single(); ok {
			return p.Offset + int64(i), int(v)
		}
		return p.Offset + int64(i), -1
	}
	return p.Offset, -1
}

func (p Pattern) matches(prefix []byte, size int64) bool {
	end := p.End()
	if end > size || end > int64(len(prefix)) {
		return false
	}
	for i, s := range p.Sets {
		if !s.Contains(prefix[p.Offset+int64(i)]) {
			return false
		}
	}
	return true
}

// Rule fires when all its patterns match.
type Rule struct {
	ID       string // stable identifier used in evidence ("cyberchef:image.jpeg.c5af3e")
	Type     string
	Level    evidence.Level // zero means Candidate
	Patterns []Pattern
	Module   string // origin, for diagnostics
}

// End is the prefix length the rule needs.
func (r Rule) End() int64 {
	var end int64
	for _, p := range r.Patterns {
		end = max(end, p.End())
	}
	return end
}

// Canonical is a stable textual form used in revision hashes.
func (r Rule) Canonical() string {
	parts := []string{r.ID, r.Type, r.level().String()}
	for _, p := range r.Patterns {
		parts = append(parts, p.Canonical())
	}
	return strings.Join(parts, " ")
}

func (r Rule) level() evidence.Level {
	if r.Level == evidence.None {
		return evidence.Candidate
	}
	return r.Level
}

// Hit is one rule match.
type Hit struct {
	Rule   string
	Type   string
	Level  evidence.Level
	Offset int64 // first pattern offset
	Length int64 // span from Offset to the end of the last pattern
}

// Matcher is an immutable compiled rule set.
type Matcher struct {
	rules   []Rule
	buckets map[[2]int64][]int
	keys    [][2]int64 // sorted bucket keys, for deterministic hits
	maxEnd  int64
}

// New compiles rules. Rules without patterns are rejected.
func New(rules []Rule) (*Matcher, error) {
	m := &Matcher{buckets: map[[2]int64][]int{}}
	for _, r := range rules {
		if len(r.Patterns) == 0 {
			return nil, fmt.Errorf("signatures: rule %q for %q has no patterns", r.ID, r.Type)
		}
		if r.Type == "" {
			return nil, fmt.Errorf("signatures: rule %q has no type", r.ID)
		}
		r.Level = r.level()
		m.rules = append(m.rules, r)
		m.maxEnd = max(m.maxEnd, r.End())
		off, fb := r.Patterns[0].firstConcrete()
		key := [2]int64{off, int64(fb)}
		if _, ok := m.buckets[key]; !ok {
			m.keys = append(m.keys, key)
		}
		m.buckets[key] = append(m.buckets[key], len(m.rules)-1)
	}
	sort.Slice(m.keys, func(i, j int) bool {
		if m.keys[i][0] != m.keys[j][0] {
			return m.keys[i][0] < m.keys[j][0]
		}
		return m.keys[i][1] < m.keys[j][1]
	})
	return m, nil
}

// MaxEnd is the prefix length needed to evaluate every rule.
func (m *Matcher) MaxEnd() int64 { return m.maxEnd }

// Rules returns the compiled rules.
func (m *Matcher) Rules() []Rule { return m.rules }

// Match evaluates every rule against prefix (the first bytes of content of
// total length size). Hits are ordered by rule position.
func (m *Matcher) Match(prefix []byte, size int64) []Hit {
	var idx []int
	for _, key := range m.keys {
		off, fb := key[0], key[1]
		if fb >= 0 && (off >= int64(len(prefix)) || int64(prefix[off]) != fb) {
			continue
		}
		idx = append(idx, m.buckets[key]...)
	}
	sort.Ints(idx)
	var hits []Hit
	for _, i := range idx {
		r := m.rules[i]
		ok := true
		for _, p := range r.Patterns {
			if !p.matches(prefix, size) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		start := r.Patterns[0].Offset
		for _, p := range r.Patterns {
			start = min(start, p.Offset)
		}
		hits = append(hits, Hit{Rule: r.ID, Type: r.Type, Level: r.Level, Offset: start, Length: r.End() - start})
	}
	return hits
}
