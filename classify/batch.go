package classify

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"sync"

	"github.com/craggy-io/classification-services/internal/cache"
)

// ClassifyMany classifies sources with Limits.Parallel workers, calling fn
// once per source (concurrently, in completion order) with its index. All
// calls share one definitions snapshot. It returns ctx.Err() if the context
// ends early; per-source errors go to fn.
func (e *Engine) ClassifyMany(ctx context.Context, sources []Source, fn func(i int, r *Result, err error), opts ...ClassifyOption) error {
	snap, err := e.current()
	if err != nil {
		return err
	}
	work := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < e.limits.Parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				r, err := e.classifyWith(ctx, snap, sources[i], opts...)
				fn(i, r, err)
			}
		}()
	}
	var ctxErr error
feed:
	for i := range sources {
		select {
		case work <- i:
		case <-ctx.Done():
			ctxErr = ctx.Err()
			break feed
		}
	}
	close(work)
	wg.Wait()
	return ctxErr
}

// ClassifyDir walks root and classifies every regular file (symbolic links
// and other special files are skipped), calling fn with each file's path.
// The walk stops at the first error fn returns, which ClassifyDir returns.
// The workdir itself is never classified.
func (e *Engine) ClassifyDir(ctx context.Context, root string, fn func(path string, r *Result, err error) error, opts ...ClassifyOption) error {
	snap, err := e.current()
	if err != nil {
		return err
	}
	workdir := e.store.Root()
	paths := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var stop error
	stopped := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return stop != nil
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for w := 0; w < e.limits.Parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				r, err := e.classifyWith(cctx, snap, File(p), opts...)
				mu.Lock()
				if stop == nil {
					if ferr := fn(p, r, err); ferr != nil {
						stop = ferr
						cancel()
					}
				}
				mu.Unlock()
			}
		}()
	}
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			mu.Lock()
			defer mu.Unlock()
			if stop == nil {
				if ferr := fn(p, nil, err); ferr != nil {
					stop = ferr
				}
			}
			if stop != nil {
				return stop
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if abs, err := filepath.Abs(p); err == nil && abs == workdir {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if stopped() {
			return fs.SkipAll
		}
		select {
		case paths <- p:
			return nil
		case <-cctx.Done():
			return fs.SkipAll
		}
	})
	close(paths)
	wg.Wait()
	switch {
	case stop != nil:
		return stop
	case walkErr != nil && !errors.Is(walkErr, fs.SkipAll):
		return walkErr
	}
	return ctx.Err()
}

// MaintenanceReport summarises a Maintain pass.
type MaintenanceReport = cache.Report

// Maintain removes cache entries that no current definition can use
// (results for replaced or removed classifiers, superseded whole-result
// entries), stat-index entries for files that changed or vanished, and
// stale spool and temp files. It is safe to run while other processes use the workdir: at worst
// they recompute an entry. It never touches definitions/.
func (e *Engine) Maintain(ctx context.Context) (MaintenanceReport, error) {
	if e.closed.Load() {
		return MaintenanceReport{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return MaintenanceReport{}, err
	}
	sp := startSpan(e.cfg.observer, nil, "maintain", e.store.Root())
	snap := e.snap.Load()
	keep := snap.entryNames()
	rep, err := e.store.Maintain(cache.Policy{
		KeepResult: func(f string) bool { return keep[f] },
	})
	sp.count("results_removed", int64(rep.ResultsRemoved))
	sp.end(err)
	return rep, err
}
