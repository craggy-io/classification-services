// Package evidence defines the shared vocabulary for how strongly a type holds
// and what else was noticed about content. It has no dependencies, so every
// other package (signatures, probes, definitions, classify) can use one Level
// type and one Anomaly type rather than translating between copies.
package evidence

import (
	"fmt"
	"strings"
)

// Level is the evidence behind a type assertion, ordered None < Candidate <
// Recognised < Validated. A signature match only reaches Candidate; a parser
// that walked the structure reaches Validated.
type Level uint8

const (
	None Level = iota
	Candidate
	Recognised
	Validated
)

var levelNames = [...]string{"none", "candidate", "recognised", "validated"}

func (l Level) String() string {
	if int(l) < len(levelNames) {
		return levelNames[l]
	}
	return fmt.Sprintf("level(%d)", uint8(l))
}

// ParseLevel parses a level name. Both "recognised" and "recognized" are
// accepted on input; output always uses "recognised".
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none", "":
		return None, nil
	case "candidate":
		return Candidate, nil
	case "recognised", "recognized":
		return Recognised, nil
	case "validated":
		return Validated, nil
	}
	return None, fmt.Errorf("evidence: unknown level %q", s)
}

// MarshalText implements encoding.TextMarshaler.
func (l Level) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (l *Level) UnmarshalText(b []byte) error {
	v, err := ParseLevel(string(b))
	if err != nil {
		return err
	}
	*l = v
	return nil
}

// Severity grades an anomaly. Info is context, Warning is suspicious, and
// Critical is a strong signal of tampering or an evasion attempt.
type Severity uint8

const (
	Info Severity = iota
	Warning
	Critical
)

var severityNames = [...]string{"info", "warning", "critical"}

func (s Severity) String() string {
	if int(s) < len(severityNames) {
		return severityNames[s]
	}
	return fmt.Sprintf("severity(%d)", uint8(s))
}

// ParseSeverity parses a severity name.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "":
		return Info, nil
	case "warning", "warn":
		return Warning, nil
	case "critical":
		return Critical, nil
	}
	return Info, fmt.Errorf("evidence: unknown severity %q", s)
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Anomaly is something notable about content that is not a type: a polyglot,
// an extension that disagrees with the content, data appended after an
// executable image, an archive entry that escapes its root. Anomalies are
// reported alongside types and never change which types hold.
//
// Codes are dotted, lower-case and stable ("zip.path-traversal",
// "extension-mismatch"); consumers switch on Code, not Message.
type Anomaly struct {
	Code     string         `json:"code"`
	Severity Severity       `json:"severity"`
	Message  string         `json:"message,omitempty"`
	By       string         `json:"by,omitempty"` // reporting classifier, or "engine"
	Metadata map[string]any `json:"metadata,omitempty"`
}
