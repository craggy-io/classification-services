package classify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/craggy-io/classification-services/catalog"
	"github.com/craggy-io/classification-services/internal/paged"
)

// classifyNode classifies one node's own content (not its children): root
// assertions, signatures, then the event-driven worklist. It returns the
// node's result and the children its derivers emitted.
func (j *job) classifyNode(c *content) (*Result, []derivedChild) {
	snap := j.snap
	sp := startSpan(j.obs, j.span, "node", c.digest)
	r := paged.New(c.ra, c.size, j.limits.MaxBytes)
	var raws []raw
	var anomalies []Anomaly
	var children []derivedChild
	var limitations []string
	complete := true

	engine := func(t string) raw {
		return raw{a: Assertion{Type: t, Level: Validated}, ev: Evidence{By: "engine", Kind: "engine", Level: Validated}}
	}
	raws = append(raws, engine(catalog.Bytes))
	if c.text {
		raws = append(raws, engine(catalog.Text))
	}
	if need := snap.matcher.MaxEnd(); need > 0 {
		prefix, err := r.ReadRange(0, need)
		if err != nil {
			complete = false
			limitations = append(limitations, fmt.Sprintf("reading signature prefix: %v", err))
		}
		hits := snap.matcher.Match(prefix, c.size)
		sp.count("signature_hits", int64(len(hits)))
		for _, h := range hits {
			raws = append(raws, raw{
				a:  Assertion{Type: h.Type, Level: h.Level},
				ev: Evidence{By: "signatures", Kind: "signature", Level: h.Level, Rule: h.Rule, Offset: h.Offset, Length: h.Length},
			})
		}
	}

	if j.depth != Quick {
		ran := make([]bool, len(snap.classifiers))
		for {
			if err := j.ctx.Err(); err != nil {
				complete = false
				limitations = append(limitations, fmt.Sprintf("classification interrupted: %v", err))
				break
			}
			// Rejected candidates still count as scheduling signals: a
			// classifier triggered by a type keeps its chance to run.
			asserted := map[string]bool{}
			for _, x := range raws {
				if !x.a.Reject && x.a.Type != "" {
					asserted[x.a.Type] = true
				}
			}
			closure := snap.catalog.Closure(asserted)
			var ready []int
			for i, ce := range snap.classifiers {
				if ran[i] {
					continue
				}
				ok := true
				for _, req := range ce.spec.Requires {
					if !closure[req] {
						ok = false
						break
					}
				}
				if ok {
					ready = append(ready, i)
				}
			}
			if len(ready) == 0 {
				break
			}
			// Stratify: a classifier requiring a type another ready
			// classifier produces waits a round, so it sees the producer's
			// validated facet rather than racing a signature candidate.
			produced := map[string]bool{}
			for _, i := range ready {
				for _, t := range snap.classifiers[i].spec.Produces {
					produced[t] = true
				}
			}
			var batch []int
			for _, i := range ready {
				ce := snap.classifiers[i]
				waits := false
				for _, req := range ce.spec.Requires {
					if produced[req] && !slices.Contains(ce.spec.Produces, req) {
						waits = true
						break
					}
				}
				if !waits {
					batch = append(batch, i)
				}
			}
			if len(batch) == 0 {
				batch = ready // mutual producers: run them together
			}
			for _, i := range batch {
				ran[i] = true
			}
			facets := matchIndex(merge(snap.catalog, c.digest, c.size, raws).Matches)
			outs := make([]outcome, len(batch))
			sem := make(chan struct{}, j.limits.Parallel)
			var wg sync.WaitGroup
			for bi, idx := range batch {
				wg.Add(1)
				go func() {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					outs[bi] = j.runClassifier(c, r, facets, snap.classifiers[idx], sp)
				}()
			}
			wg.Wait()
			for _, o := range outs { // batch is in classifier-ID order
				if o.limitation != "" {
					complete = false
					limitations = append(limitations, o.limitation)
				}
				if o.cached {
					sp.count("classifiers_cached", 1)
				} else {
					sp.count("classifiers_run", 1)
				}
				raws = append(raws, o.raws...)
				anomalies = appendAnomalies(anomalies, o.anomalies...)
				children = append(children, o.children...)
			}
		}
	}
	if r.Exhausted() {
		complete = false
		limitations = append(limitations, "read budget (MaxBytes) exhausted")
	}
	res := merge(snap.catalog, c.digest, c.size, raws)
	res.Complete = complete
	res.Limitations = sortedUnique(limitations)
	res.Anomalies = appendAnomalies(anomalies, polyglot(snap.catalog, res)...)
	sortAnomalies(res.Anomalies)
	sp.count("bytes_read", r.Pulled())
	sp.count("anomalies", int64(len(res.Anomalies)))
	sp.count("children", int64(len(children)))
	sp.end(nil)
	return res, children
}

// runClassifier runs one classifier on one node, sharing concurrent runs
// for the same content and caching the outcome per (digest, classifier
// revision). Failures, cancellations and budget-limited runs are not cached.
func (j *job) runClassifier(c *content, r *paged.Reader, facets map[string]Match, ce *entry, parent *span) outcome {
	e := j.e
	file := classifierFileName(ce)
	o, shared := e.flight.Do(c.digest+"|"+file, func() outcome {
		if b, ok := e.store.Read(c.digest, file); ok {
			if o, err := decodeOutcome(b, ce); err == nil {
				return o
			}
		}
		sp := startSpan(j.obs, parent, "classifier", ce.spec.ID)
		in := &Input{r: r, digest: c.digest, name: c.name, limits: j.limits, matches: facets}
		out, err := safeRun(j.ctx, ce, in, j.limits)
		if err != nil {
			sp.end(err)
			return outcome{limitation: fmt.Sprintf("classifier %q failed: %v", ce.spec.ID, err)}
		}
		o := outcome{}
		for _, a := range out.Assertions {
			if a, ok := j.validAssertion(ce, a); ok {
				lvl := a.Level
				if lvl == 0 {
					lvl = Recognised
					if a.Reject {
						lvl = Validated
					}
					a.Level = lvl
				}
				o.raws = append(o.raws, raw{a: a, ev: Evidence{By: ce.spec.ID, Kind: "classifier", Level: lvl}})
			}
		}
		for _, an := range out.Anomalies {
			if an.By == "" {
				an.By = ce.spec.ID
			}
			o.anomalies = appendAnomalies(o.anomalies, an)
		}
		if len(out.Derived) > 0 && !ce.spec.Derives {
			o.limitation = fmt.Sprintf("classifier %q emitted children without Derives", ce.spec.ID)
		}
		if ce.spec.Derives {
			for _, d := range out.Derived {
				dc, err := j.materialiseDerived(d, ce.spec.ID, c)
				if err != nil {
					o.limitation = fmt.Sprintf("classifier %q: deriving %q: %v", ce.spec.ID, d.Name, err)
					sp.end(err)
					return o
				}
				o.children = append(o.children, dc)
			}
		}
		if o.limitation == "" && !r.Exhausted() {
			if b, err := encodeOutcome(o); err == nil {
				_ = e.store.Write(c.digest, file, b)
			}
		}
		sp.count("children", int64(len(o.children)))
		sp.end(nil)
		return o
	})
	if shared {
		// The leader's children belong to its own job. Downgrade them to
		// descriptors; expansion re-derives bytes from this job's parent.
		o.children = slices.Clone(o.children)
		for i := range o.children {
			o.children[i].content = nil
		}
		o.cached = true
	}
	return o
}

func safeRun(ctx context.Context, ce *entry, in *Input, lim Limits) (out Output, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return ce.run(ctx, in, lim)
}

// validAssertion enforces produces-gating and catalogue membership.
func (j *job) validAssertion(ce *entry, a Assertion) (Assertion, bool) {
	a.Type = strings.TrimSpace(a.Type)
	if a.Type == "" || !j.snap.catalog.Has(a.Type) || !slices.Contains(ce.spec.Produces, a.Type) {
		return a, false
	}
	a.Metadata = sanitizeMetadata(a.Metadata)
	return a, true
}

// derivedChild is a Derived with its content materialised and hashed. A
// child decoded from the cache has a digest but no content until needed.
type derivedChild struct {
	name        string
	by          string
	speculative bool
	digest      string
	size        int64
	content     *content
}

func (j *job) materialiseDerived(d Derived, by string, parent *content) (derivedChild, error) {
	dc := derivedChild{name: d.Name, by: by, speculative: d.Speculative}
	if dc.name == "" {
		dc.name = by + " output"
	}
	var c *content
	switch {
	case d.Length > 0:
		if d.Offset < 0 || d.Offset+d.Length > parent.size {
			return dc, fmt.Errorf("range (%d, %d) outside a %d-byte parent", d.Offset, d.Length, parent.size)
		}
		ra := io.NewSectionReader(parent.ra, d.Offset, d.Length)
		digest, err := hashReaderAt(ra, d.Length)
		if err != nil {
			return dc, err
		}
		c = &content{ra: ra, size: d.Length, digest: digest}
	case d.Reader != nil:
		if d.Size < 0 {
			return dc, fmt.Errorf("negative size")
		}
		digest, err := hashReaderAt(d.Reader, d.Size)
		if err != nil {
			return dc, err
		}
		c = &content{ra: d.Reader, size: d.Size, digest: digest}
	default:
		if int64(len(d.Data)) > j.limits.MaxDerivedBytes {
			return dc, fmt.Errorf("%d bytes exceeds MaxDerivedBytes", len(d.Data))
		}
		c = &content{ra: bytes.NewReader(d.Data), size: int64(len(d.Data)), digest: sha256Hex(d.Data)}
		if c.size > j.limits.InlineChild {
			if sp, err := j.e.spool(d.Data); err == nil {
				c = sp
			}
		}
	}
	dc.content, dc.digest, dc.size = c, c.digest, c.size
	j.track(c)
	return dc, nil
}

// spool writes data to a temporary file and returns content over it.
func (e *Engine) spool(data []byte) (*content, error) {
	f, err := os.CreateTemp(e.store.SpoolDir(), "child-*")
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return &content{ra: f, size: int64(len(data)), digest: sha256Hex(data), spool: f.Name(), close: f.Close}, nil
}

// polyglot reports content validated as two unrelated formats: types where
// neither descends from the other and they share no ancestor but "bytes"
// (an ELF that is also a ZIP, a PDF that is also a JPEG).
func polyglot(cat *catalog.Catalog, r *Result) []Anomaly {
	var validated []string
	for _, m := range r.Matches {
		if m.Direct && m.Level == Validated && m.Type != catalog.Bytes && m.Type != catalog.Text {
			if info, ok := cat.Get(m.Type); ok && !info.Abstract {
				validated = append(validated, m.Type)
			}
		}
	}
	related := func(a, b string) bool {
		if cat.IsA(a, b) || cat.IsA(b, a) {
			return true
		}
		for _, x := range cat.Ancestors(a) {
			if x != catalog.Bytes && x != catalog.Text && cat.IsA(b, x) {
				return true
			}
		}
		return false
	}
	var unrelated []string
	for i, a := range validated {
		for _, b := range validated[i+1:] {
			if !related(a, b) {
				unrelated = append(unrelated, a, b)
			}
		}
	}
	unrelated = sortedUnique(unrelated)
	if len(unrelated) == 0 {
		return nil
	}
	return []Anomaly{{
		Code: "polyglot", Severity: Warning, By: "engine",
		Message:  "the content is valid as unrelated formats: " + strings.Join(unrelated, ", "),
		Metadata: map[string]any{"types": unrelated},
	}}
}

// extensionMismatch reports a name hint whose extension is claimed only by
// types unrelated to anything the content was shown to be.
func extensionMismatch(cat *catalog.Catalog, r *Result, name string) []Anomaly {
	ext := ""
	if i := strings.LastIndexByte(name, '.'); i > 0 && i < len(name)-1 {
		ext = strings.ToLower(name[i+1:])
	}
	if ext == "" || r.Primary == "" || r.Primary == catalog.Bytes {
		return nil
	}
	claimants := cat.ByExtension(ext)
	if len(claimants) == 0 {
		return nil
	}
	for _, m := range r.Matches {
		// Abstract namespaces are too broad to vouch for an extension: an
		// ELF named .exe is still a mismatch although both are executables.
		if info, ok := cat.Get(m.Type); !ok || info.Abstract {
			continue
		}
		for _, cl := range claimants {
			if cat.IsA(cl, m.Type) || cat.IsA(m.Type, cl) {
				return nil
			}
		}
	}
	sev := Warning
	if cat.IsA(r.Primary, "executable") {
		sev = Critical
		for _, cl := range claimants {
			if cat.IsA(cl, "executable") {
				sev = Warning
			}
		}
	}
	sort.Strings(claimants)
	return []Anomaly{{
		Code: "extension-mismatch", Severity: sev, By: "engine",
		Message:  fmt.Sprintf("the name ends in .%s but the content is %s", ext, r.Primary),
		Metadata: map[string]any{"extension": ext, "expected": first(claimants, 10), "primary": r.Primary},
	}}
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
