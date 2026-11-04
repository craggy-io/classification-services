package classify

import (
	"context"
	"fmt"
	"sync"
)

// job is one top-level Classify call: the root node plus the breadth-first
// expansion of derived content into a DAG keyed by digest.
type job struct {
	e       *Engine
	snap    *snapshot
	ctx     context.Context
	depth   Depth
	recurse func(path []string, c Child) bool
	limits  Limits
	obs     Observer
	span    *span

	nodes        map[string]*Result // digest -> shared result
	fresh        []*Result          // nodes classified (not loaded) by this job
	totalNodes   int
	derivedBytes int64
	rederived    map[string][]derivedChild // parent digest|deriver -> children

	mu       sync.Mutex
	contents []*content // derived contents to close when the job ends
}

func (j *job) track(c *content) {
	j.mu.Lock()
	j.contents = append(j.contents, c)
	j.mu.Unlock()
}

func (j *job) close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range j.contents {
		c.Close()
	}
	j.contents = nil
}

type pending struct {
	parent    *Result
	parentC   *content
	slot      int // index in parent.Children
	child     derivedChild
	path      []string // parent's path
	ancestors map[string]bool
	depth     int
}

const droppedSlot = "\x00dropped"

func (j *job) run(root *content) *Result {
	j.nodes = map[string]*Result{}
	j.rederived = map[string][]derivedChild{}
	// A name hint is visible to classifiers via Input.Name(), so a named
	// root's result is not a function of its digest alone: never serve or
	// store it via the digest-keyed whole-result caches.
	cacheable := j.recurse == nil && root.name == ""

	if cacheable {
		if r := j.e.lruGet(root.digest, j.snap.revision, j.depth, root.text); r != nil {
			j.span.count("cache_hit", 1)
			return r
		}
		if r := j.e.loadNode(root.digest, j.snap.revision, j.depth, root.text); r != nil {
			j.span.count("cache_hit", 1)
			j.e.lruPut(root.digest, j.snap.revision, j.depth, root.text, r)
			return r
		}
	}

	res, derived := j.classifyNode(root)
	j.register(res, true)
	j.totalNodes = 1
	var queue []pending
	j.expand(&queue, res, root, derived, nil, map[string]bool{root.digest: true}, 0)
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		j.expandOne(&queue, p)
	}
	j.pruneSpeculative(res)
	j.pruneDropped(res)
	j.span.count("nodes", int64(len(j.nodes)))

	if j.recurse == nil {
		// Fresh child nodes are name-independent (derived contents are
		// unnamed), so they are stored even for a named root; the named
		// root itself is excluded below.
		for _, n := range j.fresh {
			if n == res && root.name != "" {
				continue
			}
			if subtreeComplete(n) {
				j.e.storeNode(n, j.snap.revision, j.depth, n == res && root.text)
			}
		}
	}
	if cacheable && subtreeComplete(res) {
		j.e.lruPut(root.digest, j.snap.revision, j.depth, root.text, res)
	}
	return res
}

func subtreeComplete(r *Result) bool {
	ok := true
	_ = r.Walk(func(_ []string, n *Result) error {
		if !n.Complete {
			ok = false
		}
		return nil
	})
	return ok
}

// expand queues a node's children, applying the per-node limits.
func (j *job) expand(queue *[]pending, parent *Result, parentC *content, derived []derivedChild, path []string, ancestors map[string]bool, depth int) {
	if j.depth == Quick || len(derived) == 0 {
		return
	}
	if parentC != nil && parentC.size > 0 {
		budget := j.limits.MaxExpansion * float64(parentC.size)
		var total float64
		var keep []derivedChild
		for _, d := range derived {
			if total+float64(d.size) <= budget {
				keep = append(keep, d)
				total += float64(d.size)
			}
		}
		if len(keep) < len(derived) {
			parent.Complete = false
			parent.Limitations = sortedUnique(append(parent.Limitations,
				fmt.Sprintf("derived content exceeds MaxExpansion (%gx)", j.limits.MaxExpansion)))
			derived = keep
		}
	}
	if len(derived) > j.limits.MaxChildren {
		parent.Complete = false
		parent.Limitations = sortedUnique(append(parent.Limitations,
			fmt.Sprintf("derived children truncated at MaxChildren (%d)", j.limits.MaxChildren)))
		derived = derived[:j.limits.MaxChildren]
	}
	base := len(parent.Children)
	for i, d := range derived {
		parent.Children = append(parent.Children, Child{Name: d.name, By: d.by, Speculative: d.speculative})
		*queue = append(*queue, pending{parent: parent, parentC: parentC, slot: base + i, child: d, path: path, ancestors: ancestors, depth: depth + 1})
	}
}

func (j *job) expandOne(queue *[]pending, p pending) {
	slot := &p.parent.Children[p.slot]
	d := p.child
	drop := func(limitation string) {
		slot.Name, slot.Result = droppedSlot, nil
		if limitation != "" {
			p.parent.Complete = false
			p.parent.Limitations = sortedUnique(append(p.parent.Limitations, limitation))
		}
	}
	switch {
	case d.speculative && j.depth != Deep:
		drop("")
		return
	case p.depth > j.limits.MaxDepth:
		drop(fmt.Sprintf("derivation depth exceeds MaxDepth (%d)", j.limits.MaxDepth))
		return
	case j.ctx.Err() != nil:
		drop(fmt.Sprintf("classification interrupted: %v", j.ctx.Err()))
		return
	}
	if j.recurse != nil && !j.recurse(append([]string(nil), p.path...), Child{Name: d.name, By: d.by, Speculative: d.speculative, Result: &Result{Digest: d.digest, Size: d.size}}) {
		drop("")
		return
	}
	if p.ancestors[d.digest] {
		drop(fmt.Sprintf("derived content %q is its own ancestor (cycle)", d.name))
		return
	}
	if existing, ok := j.nodes[d.digest]; ok {
		slot.Result = existing
		return
	}
	if j.totalNodes >= j.limits.MaxNodes {
		drop(fmt.Sprintf("derived nodes exceed MaxNodes (%d)", j.limits.MaxNodes))
		return
	}
	if j.derivedBytes+d.size > j.limits.MaxDerivedBytes {
		drop(fmt.Sprintf("derived bytes exceed MaxDerivedBytes (%d)", j.limits.MaxDerivedBytes))
		return
	}
	j.totalNodes++
	j.derivedBytes += d.size
	if j.recurse == nil {
		if r := j.e.loadNode(d.digest, j.snap.revision, j.depth, false); r != nil {
			// A cached subtree counts fully against this job's limits and
			// must not reintroduce an ancestor (cycle).
			var extraNodes int
			var extraBytes int64
			cycle := false
			_ = r.Walk(func(_ []string, n *Result) error {
				if p.ancestors[n.Digest] {
					cycle = true
				}
				if n.Digest != d.digest {
					if _, ok := j.nodes[n.Digest]; !ok {
						extraNodes++
						extraBytes += n.Size
					}
				}
				return nil
			})
			switch {
			case cycle:
				drop(fmt.Sprintf("derived content %q is its own ancestor (cycle)", d.name))
				return
			case j.totalNodes+extraNodes > j.limits.MaxNodes:
				drop(fmt.Sprintf("derived nodes exceed MaxNodes (%d)", j.limits.MaxNodes))
				return
			case j.derivedBytes+extraBytes > j.limits.MaxDerivedBytes:
				drop(fmt.Sprintf("derived bytes exceed MaxDerivedBytes (%d)", j.limits.MaxDerivedBytes))
				return
			}
			j.totalNodes += extraNodes
			j.derivedBytes += extraBytes
			slot.Result = r
			_ = r.Walk(func(_ []string, n *Result) error { j.register(n, false); return nil })
			return
		}
	}
	cc := d.content
	if cc == nil {
		if cc = j.rederive(p.parentC, d); cc == nil {
			drop(fmt.Sprintf("could not re-derive %q", d.name))
			return
		}
	}
	res, derived := j.classifyNode(cc)
	slot.Result = res
	j.register(res, true)
	anc := make(map[string]bool, len(p.ancestors)+1)
	for a := range p.ancestors {
		anc[a] = true
	}
	anc[res.Digest] = true
	j.expand(queue, res, cc, derived, append(append([]string(nil), p.path...), d.name), anc, p.depth)
}

func (j *job) register(r *Result, fresh bool) {
	if _, ok := j.nodes[r.Digest]; ok {
		return
	}
	j.nodes[r.Digest] = r
	if fresh {
		j.fresh = append(j.fresh, r)
	}
}

// rederive runs a deriver again to recover a child's bytes when only its
// cached descriptor is known.
func (j *job) rederive(parent *content, d derivedChild) *content {
	ce := j.snap.byID[d.by]
	if parent == nil || ce == nil {
		return nil
	}
	key := parent.digest + "|" + d.by
	children, ok := j.rederived[key]
	if !ok {
		in := &Input{r: newReader(parent, j.limits), digest: parent.digest, name: parent.name, limits: j.limits, matches: map[string]Match{}}
		out, err := safeRun(j.ctx, ce, in, j.limits)
		if err == nil {
			for _, dv := range out.Derived {
				if dc, err := j.materialiseDerived(dv, d.by, parent); err == nil {
					children = append(children, dc)
				}
			}
		}
		j.rederived[key] = children
	}
	for _, ch := range children {
		if ch.digest == d.digest {
			return ch.content
		}
	}
	return nil
}

// pruneSpeculative drops speculative children (at Deep) that turned out to
// be nothing more than bytes or text and have no kept children of their own.
func (j *job) pruneSpeculative(root *Result) {
	if j.depth != Deep {
		return
	}
	seen := map[*Result]bool{}
	var prune func(*Result)
	prune = func(r *Result) {
		if r == nil || seen[r] {
			return
		}
		seen[r] = true
		for _, c := range r.Children {
			prune(c.Result)
		}
		kept := r.Children[:0]
		for _, c := range r.Children {
			if c.Speculative && c.Result != nil && !worthKeeping(c.Result) {
				continue
			}
			kept = append(kept, c)
		}
		r.Children = kept
	}
	prune(root)
}

func worthKeeping(r *Result) bool {
	for _, c := range r.Children {
		if c.Result != nil && c.Name != droppedSlot {
			return true
		}
	}
	for _, m := range r.Matches {
		if m.Type != "bytes" && m.Type != "text" && m.Level >= Recognised {
			return true
		}
	}
	return false
}

func (j *job) pruneDropped(root *Result) {
	seen := map[*Result]bool{}
	var walk func(*Result)
	walk = func(r *Result) {
		if r == nil || seen[r] {
			return
		}
		seen[r] = true
		kept := r.Children[:0]
		for _, c := range r.Children {
			if c.Result != nil && c.Name != droppedSlot {
				kept = append(kept, c)
			}
		}
		r.Children = kept
		for _, c := range r.Children {
			walk(c.Result)
		}
	}
	walk(root)
}
