package classify

import (
	"context"
	"io"

	"github.com/craggy-io/classification-services/defs"
	"github.com/craggy-io/classification-services/probes"
	"github.com/craggy-io/classification-services/signatures"
)

// builtinClassifiers adapts every built-in probe to a native classifier.
func builtinClassifiers() []Classifier {
	var out []Classifier
	for _, p := range probes.Builtins() {
		run := p.Run
		out = append(out, ClassifierFunc{
			S: Spec{ID: p.ID, Produces: p.Produces, Requires: p.Requires, Derives: p.Derives, Revision: probes.Revision},
			Run: func(ctx context.Context, in *Input) (Output, error) {
				findings, err := run(ctx, probeInput{in})
				if err != nil {
					return Output{}, err
				}
				var out Output
				for _, f := range findings {
					if f.Type != "" {
						out.Assertions = append(out.Assertions, Assertion{Type: f.Type, Level: f.Level, Metadata: f.Metadata, Reject: f.Reject})
					}
					for _, d := range f.Children {
						out.Derived = append(out.Derived, Derived{Name: d.Name, Data: d.Data, Offset: d.Offset, Length: d.Length, Speculative: d.Speculative})
					}
					out.Anomalies = append(out.Anomalies, f.Anomalies...)
				}
				return out, nil
			},
		})
	}
	return out
}

// probeInput adapts *Input to probes.Input.
type probeInput struct{ in *Input }

func (p probeInput) Size() int64                       { return p.in.Size() }
func (p probeInput) Name() string                      { return p.in.Name() }
func (p probeInput) Prefix(n int64) ([]byte, error)    { return p.in.Prefix(n) }
func (p probeInput) Read(off, n int64) ([]byte, error) { return p.in.Read(off, n) }
func (p probeInput) Text(limit int64) (string, error)  { return p.in.Text(limit) }
func (p probeInput) JSON(limit int64) (any, error)     { return p.in.JSON(limit) }
func (p probeInput) View(name string) (any, error)     { return p.in.View(name) }
func (p probeInput) Reader() io.ReaderAt               { return p.in.r }
func (p probeInput) Limits() probes.Limits {
	l := p.in.limits
	return probes.Limits{MaxBytes: l.MaxBytes, MaxDerivedBytes: l.MaxDerivedBytes, MaxExpansion: l.MaxExpansion}
}

func builtinSignatures() ([]signatures.Rule, error) {
	rules, _, err := signatures.ParseCyberChef(defs.CyberChef(), "cyberchef")
	return rules, err
}
