package signatures

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"

	"github.com/craggy-io/foundation-kit/bundle"
	"github.com/craggy-io/foundation-kit/kind"

	"github.com/craggy-io/classification-services/evidence"
)

// CyberChefKind is the bundle kind of a CyberChef signature set: a JSON file
// in the CyberChefFile format, compiled into its rules. It is global, so
// sets are named by contribution ID alone.
var CyberChefKind = kind.New[[]Rule]("classify.cyberchef", 1, kind.Global())

// CodeCyberChefInvalid is the diagnostic code for a set that does not parse.
const CodeCyberChefInvalid bundle.Code = "classify.cyberchef_invalid"

// CompileCyberChef is CyberChefKind's bundle compiler. It parses the file
// with ParseCyberChef, using the contribution ID as the rules' module.
func CompileCyberChef(_ context.Context, c bundle.Contribution) (bundle.Compiled[[]Rule], []bundle.Diagnostic) {
	data, err := fs.ReadFile(c.Files, c.Path)
	if err == nil {
		var rules []Rule
		if rules, _, err = ParseCyberChef(data, c.Ref.ID); err == nil {
			return bundle.Compiled[[]Rule]{Value: rules}, nil
		}
	}
	return bundle.Compiled[[]Rule]{}, []bundle.Diagnostic{{Code: CodeCyberChefInvalid, Path: c.Path, Message: err.Error()}}
}

// CyberChefFile is the imported CyberChef FileSignatures set (Apache-2.0),
// with each rule targeting a type in this module's catalogue.
type CyberChefFile struct {
	Version        int             `json:"version"`
	Source         string          `json:"source"`
	SourceRevision string          `json:"source_revision"`
	Rules          []CyberChefRule `json:"rules"`
}

// CyberChefRule is one signature: any alternative matching fires the rule.
type CyberChefRule struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Alternatives [][]CyberChefCond `json:"alternatives"`
}

// CyberChefCond is one absolute-offset byte condition.
type CyberChefCond struct {
	Offset  int64  `json:"offset"`
	Op      string `json:"op"`
	Value   int    `json:"value"`
	Values  []int  `json:"values,omitempty"`
	Minimum *int   `json:"minimum,omitempty"`
	Maximum *int   `json:"maximum,omitempty"`
}

func (c CyberChefCond) set() (ByteSet, error) {
	byteVal := func(v int) (byte, error) {
		if v < 0 || v > 255 {
			return 0, fmt.Errorf("byte value %d out of range", v)
		}
		return byte(v), nil
	}
	switch c.Op {
	case "equal":
		v, err := byteVal(c.Value)
		return Only(v), err
	case "one_of":
		if len(c.Values) == 0 {
			return ByteSet{}, fmt.Errorf("one_of with no values")
		}
		var s ByteSet
		for _, x := range c.Values {
			v, err := byteVal(x)
			if err != nil {
				return s, err
			}
			s = s.Add(v)
		}
		return s, nil
	case "not_equal":
		v, err := byteVal(c.Value)
		return Any().Remove(v), err
	case "range":
		lo, hi := 0, 255
		if c.Minimum != nil {
			lo = *c.Minimum
		}
		if c.Maximum != nil {
			hi = *c.Maximum
		}
		if lo < 0 || hi > 255 || lo > hi {
			return ByteSet{}, fmt.Errorf("invalid range [%d,%d]", lo, hi)
		}
		var s ByteSet
		for v := lo; v <= hi; v++ {
			s = s.Add(byte(v))
		}
		return s, nil
	}
	return ByteSet{}, fmt.Errorf("unsupported condition op %q", c.Op)
}

// alternative turns a list of absolute-offset conditions into one contiguous
// pattern; unconditioned positions in between are wildcards.
func alternative(conds []CyberChefCond) (Pattern, error) {
	if len(conds) == 0 {
		return Pattern{}, fmt.Errorf("empty alternative")
	}
	lo, hi := conds[0].Offset, conds[0].Offset
	for _, c := range conds {
		if c.Offset < 0 {
			return Pattern{}, fmt.Errorf("negative offset %d", c.Offset)
		}
		lo, hi = min(lo, c.Offset), max(hi, c.Offset)
	}
	if hi-lo > 1<<16 {
		return Pattern{}, fmt.Errorf("alternative spans %d bytes", hi-lo)
	}
	sets := make([]ByteSet, hi-lo+1)
	for i := range sets {
		sets[i] = Any()
	}
	for _, c := range conds {
		s, err := c.set()
		if err != nil {
			return Pattern{}, err
		}
		sets[c.Offset-lo] = sets[c.Offset-lo].Intersect(s)
		if sets[c.Offset-lo].IsEmpty() {
			return Pattern{}, fmt.Errorf("contradictory conditions at offset %d match no byte", c.Offset)
		}
	}
	return Pattern{Offset: lo, Sets: sets}, nil
}

// ParseCyberChef converts the JSON signature set into rules: one rule per
// alternative, each at Candidate level.
func ParseCyberChef(data []byte, module string) ([]Rule, *CyberChefFile, error) {
	var file CyberChefFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, nil, fmt.Errorf("signatures: parsing CyberChef set: %w", err)
	}
	var rules []Rule
	for _, r := range file.Rules {
		for i, alt := range r.Alternatives {
			p, err := alternative(alt)
			if err != nil {
				return nil, nil, fmt.Errorf("signatures: CyberChef rule %q: %w", r.ID, err)
			}
			id := "cyberchef:" + r.ID
			if len(r.Alternatives) > 1 {
				id = fmt.Sprintf("%s#%d", id, i)
			}
			rules = append(rules, Rule{ID: id, Type: r.Type, Level: evidence.Candidate, Patterns: []Pattern{p}, Module: module})
		}
	}
	return rules, &file, nil
}
