package classify

import (
	"encoding/json"
	"fmt"

	"github.com/craggy-io/classification-services/internal/cache"
)

// codecVersion is part of every cache entry name; bump it when the encoding
// changes so old entries are ignored and later removed by Maintain.
const codecVersion = "c1"

func classifierFileName(ce *entry) string {
	return cache.ClassifierFile(ce.spec.ID, codecVersion+"-"+ce.rev)
}

func nodeFileName(snapRev string, d Depth, text bool) string {
	return cache.NodeFile(fmt.Sprintf("%s-%s-%s-%t", codecVersion, snapRev, d, text))
}

// sanitizeMetadata round-trips metadata through JSON so cached and fresh
// results are identical (int becomes float64 either way, unrepresentable
// values are dropped).
func sanitizeMetadata(md map[string]any) map[string]any {
	if len(md) == 0 {
		return nil
	}
	b, err := json.Marshal(md)
	if err != nil {
		out := map[string]any{}
		for k, v := range md {
			if vb, err := json.Marshal(v); err == nil {
				var x any
				if json.Unmarshal(vb, &x) == nil {
					out[k] = x
				}
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil || len(out) == 0 {
		return nil
	}
	return out
}

// --- per-classifier entries ---

type cachedChild struct {
	Name        string `json:"name"`
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	Speculative bool   `json:"speculative,omitempty"`
}

type cachedOutput struct {
	Assertions []cachedAssertion `json:"assertions"`
	Children   []cachedChild     `json:"children,omitempty"`
	Anomalies  []Anomaly         `json:"anomalies,omitempty"`
}

type cachedAssertion struct {
	Type     string         `json:"type"`
	Level    Level          `json:"level"`
	Reject   bool           `json:"reject,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// outcome is one classifier run on one content node, fresh or cached.
type outcome struct {
	raws       []raw
	children   []derivedChild
	anomalies  []Anomaly
	limitation string
	cached     bool
	exhausted  bool // the run hit its read budget; not shareable or cacheable
}

func encodeOutcome(o outcome) ([]byte, error) {
	c := cachedOutput{Assertions: []cachedAssertion{}, Anomalies: o.anomalies}
	for _, r := range o.raws {
		c.Assertions = append(c.Assertions, cachedAssertion{Type: r.a.Type, Level: r.a.Level, Reject: r.a.Reject, Metadata: r.a.Metadata})
	}
	for _, d := range o.children {
		c.Children = append(c.Children, cachedChild{Name: d.name, Digest: d.digest, Size: d.size, Speculative: d.speculative})
	}
	return json.Marshal(c)
}

func decodeOutcome(b []byte, ce *entry) (outcome, error) {
	var c cachedOutput
	if err := json.Unmarshal(b, &c); err != nil {
		return outcome{}, err
	}
	o := outcome{anomalies: c.Anomalies, cached: true}
	for _, a := range c.Assertions {
		o.raws = append(o.raws, raw{
			a:  Assertion{Type: a.Type, Level: a.Level, Reject: a.Reject, Metadata: a.Metadata},
			ev: Evidence{By: ce.spec.ID, Kind: "classifier", Level: a.Level},
		})
	}
	for _, ch := range c.Children {
		o.children = append(o.children, derivedChild{name: ch.Name, by: ce.spec.ID, digest: ch.Digest, size: ch.Size, speculative: ch.Speculative})
	}
	return o, nil
}

// --- whole-result entries ---

type cachedNode struct {
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Primary     string            `json:"primary"`
	Matches     []Match           `json:"matches"`
	Rejected    []Rejection       `json:"rejected,omitempty"`
	Anomalies   []Anomaly         `json:"anomalies,omitempty"`
	Children    []cachedNodeChild `json:"children,omitempty"`
	Complete    bool              `json:"complete"`
	Limitations []string          `json:"limitations,omitempty"`
}

// cachedNodeChild refers to its node by digest: the DAG is stored once per
// entry as a flat node table, so shared children are not duplicated.
type cachedNodeChild struct {
	Name        string `json:"name"`
	By          string `json:"by"`
	Speculative bool   `json:"speculative,omitempty"`
	Digest      string `json:"digest"`
}

type cachedDAG struct {
	Root  string                 `json:"root"`
	Nodes map[string]*cachedNode `json:"nodes"`
}

func encodeDAG(r *Result) ([]byte, error) {
	dag := cachedDAG{Root: r.Digest, Nodes: map[string]*cachedNode{}}
	err := r.Walk(func(_ []string, n *Result) error {
		if _, ok := dag.Nodes[n.Digest]; ok {
			return nil
		}
		cn := &cachedNode{
			Digest: n.Digest, Size: n.Size, Primary: n.Primary, Matches: n.Matches,
			Rejected: n.Rejected, Anomalies: n.Anomalies, Complete: n.Complete, Limitations: n.Limitations,
		}
		for _, c := range n.Children {
			cn.Children = append(cn.Children, cachedNodeChild{Name: c.Name, By: c.By, Speculative: c.Speculative, Digest: c.Digest})
		}
		dag.Nodes[n.Digest] = cn
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(dag)
}

func decodeDAG(b []byte, digest string) (*Result, error) {
	var dag cachedDAG
	if err := json.Unmarshal(b, &dag); err != nil {
		return nil, err
	}
	if dag.Root != digest || dag.Nodes[digest] == nil {
		return nil, fmt.Errorf("classify: cache entry root mismatch")
	}
	built := map[string]*Result{}
	inProgress := map[string]bool{}
	var build func(d string, depth int) (*Result, error)
	build = func(d string, depth int) (*Result, error) {
		if r, ok := built[d]; ok {
			return r, nil
		}
		if inProgress[d] {
			return nil, fmt.Errorf("classify: corrupt cache entry (cycle at %s)", d)
		}
		n := dag.Nodes[d]
		if n == nil || depth > 64 || n.Digest != d {
			return nil, fmt.Errorf("classify: corrupt cache entry")
		}
		inProgress[d] = true
		r := &Result{
			Digest: n.Digest, Size: n.Size, Primary: n.Primary, Matches: n.Matches,
			Rejected: n.Rejected, Anomalies: n.Anomalies, Complete: n.Complete, Limitations: n.Limitations,
		}
		for _, c := range n.Children {
			cr, err := build(c.Digest, depth+1)
			if err != nil {
				return nil, err
			}
			r.Children = append(r.Children, Child{Name: c.Name, By: c.By, Speculative: c.Speculative, Result: cr})
		}
		delete(inProgress, d)
		built[d] = r
		return r, nil
	}
	return build(digest, 0)
}
