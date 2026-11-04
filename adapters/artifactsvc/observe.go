package artifactsvc

import (
	"context"
	"sync"

	"github.com/craggy-io/artifact-services/observability"

	"github.com/craggy-io/classification-services/classify"
)

// Layer is the observability scope layer for classification work.
const Layer = "classification"

// Observer returns a classify.Observer that mirrors classification events as
// artifact-services observability spans under ctx (which carries the
// observer/collector set with observability.With). Nested classification
// operations become child spans; counters are reported with Span.Count.
//
//	ctx = observability.With(ctx, observability.Options{Collector: metrics})
//	r, err := engine.Classify(ctx, src, classify.Observe(artifactsvc.Observer(ctx)))
//
// Cache maintenance and the per-classifier runs are marked Internal, so
// default reporting shows classify calls, nodes and definition changes.
func Observer(ctx context.Context) classify.Observer {
	type open struct {
		ctx  context.Context
		span *observability.Span
	}
	var mu sync.Mutex
	spans := map[uint64]open{}
	return func(ev classify.Event) {
		mu.Lock()
		defer mu.Unlock()
		if !ev.Final {
			parent := ctx
			if p, ok := spans[ev.ParentID]; ok {
				parent = p.ctx
			}
			if ev.Op == "classifier" || ev.Op == "maintain" {
				parent = observability.WithInternal(parent)
			}
			c, s := observability.Start(parent, observability.Scope{Layer: Layer, Operation: ev.Op}, ev.Key)
			spans[ev.ID] = open{c, s}
			return
		}
		o, ok := spans[ev.ID]
		if !ok {
			return
		}
		delete(spans, ev.ID)
		for k, v := range ev.Counters {
			if k == "bytes_read" {
				o.span.AddBytes(v)
				continue
			}
			o.span.Count(k, v)
		}
		o.span.End(ev.Err)
	}
}
