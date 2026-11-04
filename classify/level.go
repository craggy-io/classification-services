package classify

import (
	"fmt"
	"strings"

	"github.com/craggy-io/classification-services/catalog"
	"github.com/craggy-io/classification-services/evidence"
)

// Level is the evidence behind a type: Candidate < Recognised < Validated.
type Level = evidence.Level

// Evidence levels.
const (
	Candidate  = evidence.Candidate
	Recognised = evidence.Recognised
	Validated  = evidence.Validated
)

// Anomaly is something notable about content that is not a type.
type Anomaly = evidence.Anomaly

// Severity grades an anomaly.
type Severity = evidence.Severity

// Anomaly severities.
const (
	Info     = evidence.Info
	Warning  = evidence.Warning
	Critical = evidence.Critical
)

// TypeInfo describes one catalogue type.
type TypeInfo = catalog.TypeInfo

// Depth says how far classification goes. It is a separate type from Level
// so the two cannot be confused.
type Depth uint8

const (
	// Standard runs classifiers and structural derivation (the default).
	Standard Depth = iota
	// Quick runs signatures only and derives nothing.
	Quick
	// Deep adds speculative derivations (base64/hex decodings of text).
	Deep
)

var depthNames = [...]string{"standard", "quick", "deep"}

func (d Depth) String() string {
	if int(d) < len(depthNames) {
		return depthNames[d]
	}
	return fmt.Sprintf("depth(%d)", uint8(d))
}

// ParseDepth parses "quick", "standard" or "deep".
func ParseDepth(s string) (Depth, error) {
	for i, n := range depthNames {
		if strings.EqualFold(strings.TrimSpace(s), n) {
			return Depth(i), nil
		}
	}
	return Standard, fmt.Errorf("classify: unknown depth %q", s)
}

// MarshalText implements encoding.TextMarshaler.
func (d Depth) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Depth) UnmarshalText(b []byte) error {
	v, err := ParseDepth(string(b))
	if err != nil {
		return err
	}
	*d = v
	return nil
}
