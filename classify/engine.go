// Package classify takes any input (a file, bytes or text) and returns every
// type it can be shown to be, as a DAG: an APK is also a ZIP, and a ZIP is
// also bytes. Content found inside the input (archive entries, decompressed
// payloads, executable overlays) is classified recursively into a content
// DAG, and anomalies (polyglots, path traversal, extension mismatches,
// active PDF content) are reported alongside types.
//
// Built-in definitions are embedded. New definitions, written in Starlark,
// can be checked against their inline tests, previewed against known
// content and installed at runtime without restarting. Results are cached in
// a caller-supplied working folder that several processes may share.
//
//	e, err := classify.Open(ctx, workdir)
//	defer e.Close()
//	r, err := e.Classify(ctx, classify.File("app.apk"))
//	r.Is("archive.zip")                 // true: android.apk descends from it
//	r.Primary                           // "android.apk"
//	ex, _ := r.Explain("android.apk")   // why
package classify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/craggy-io/classification-services/catalog"
	"github.com/craggy-io/classification-services/definitions"
	"github.com/craggy-io/classification-services/defs"
	"github.com/craggy-io/classification-services/internal/cache"
	"github.com/craggy-io/classification-services/internal/flight"
	"github.com/craggy-io/classification-services/internal/paged"
	"github.com/craggy-io/classification-services/signatures"
)

// ErrClosed is returned by operations on a closed Engine.
var ErrClosed = errors.New("classify: engine closed")

// Engine classifies content against a snapshot of definitions. It is safe
// for concurrent use.
type Engine struct {
	store  *cache.Store
	cfg    engineConfig
	limits Limits

	snap    atomic.Pointer[snapshot]
	mu      sync.Mutex                     // serialises snapshot rebuilds
	base    map[string]*definitions.Module // built-in and WithDefinitions modules
	natives []Classifier
	sigs    []signatures.Rule // built-in CyberChef rules

	persisted   string       // fingerprint of definitions/ at the last load
	lastRefresh atomic.Int64 // unix nanos

	flight flight.Group[outcome]
	closed atomic.Bool

	lruMu sync.Mutex
	lru   map[string]*Result
	order []string
}

const lruCapacity = 256

// Open loads the built-in definitions, any WithDefinitions modules and the
// modules persisted under workdir/definitions, and prepares the cache.
// workdir is required; it is created if missing.
func Open(ctx context.Context, workdir string, opts ...Option) (*Engine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg := engineConfig{builtins: true}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	st, err := cache.Open(workdir)
	if err != nil {
		return nil, err
	}
	e := &Engine{store: st, cfg: cfg, limits: cfg.limits.withDefaults(), base: map[string]*definitions.Module{}, lru: map[string]*Result{}}
	sp := startSpan(cfg.observer, nil, "open", st.Root())
	if cfg.builtins {
		mods, err := definitions.LoadFS(defs.FS(), st)
		if err != nil {
			sp.end(err)
			return nil, fmt.Errorf("classify: loading built-in definitions: %w", err)
		}
		for _, m := range mods {
			e.base[m.Name] = m
		}
		if e.sigs, err = builtinSignatures(); err != nil {
			sp.end(err)
			return nil, err
		}
	}
	for _, fsys := range cfg.defFS {
		mods, err := definitions.LoadFS(fsys, st)
		if err != nil {
			sp.end(err)
			return nil, err
		}
		for _, m := range mods {
			e.base[m.Name] = m
		}
	}
	e.natives = append(e.natives, cfg.classifiers...)
	if cfg.builtins {
		e.natives = append(e.natives, builtinClassifiers()...)
	}
	if err := e.reload(); err != nil {
		sp.end(err)
		return nil, err
	}
	sp.end(nil)
	return e, nil
}

// reload rebuilds the snapshot from base modules plus persisted ones.
// Callers hold e.mu (or are Open).
func (e *Engine) reload() error {
	persisted, fp, err := e.loadPersisted()
	if err != nil {
		return err
	}
	effective := make(map[string]*definitions.Module, len(e.base)+len(persisted))
	for n, m := range e.base {
		effective[n] = m
	}
	for _, m := range persisted {
		effective[m.Name] = m
	}
	snap, err := buildSnapshot(effective, e.natives, e.sigs)
	if err != nil {
		return err
	}
	e.install(snap)
	e.persisted = fp
	e.lastRefresh.Store(time.Now().UnixNano())
	return nil
}

func (e *Engine) install(s *snapshot) {
	e.snap.Store(s)
	e.lruMu.Lock()
	e.lru, e.order = map[string]*Result{}, nil
	e.lruMu.Unlock()
}

func (e *Engine) loadPersisted() ([]*definitions.Module, string, error) {
	dir := e.store.DefinitionsDir()
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var mods []*definitions.Module
	var fp []string
	for _, ent := range ents {
		name := ent.Name()
		if ent.IsDir() || filepath.Ext(name) != ".star" {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, "", err
		}
		m, err := definitions.Load(name[:len(name)-len(".star")], src, e.store)
		if err != nil {
			return nil, "", fmt.Errorf("classify: persisted definition %s: %w", name, err)
		}
		mods = append(mods, m)
		fp = append(fp, m.Name+"@"+m.SourceHash)
	}
	sort.Strings(fp)
	return mods, fmt.Sprint(fp), nil
}

// Close releases the engine. It is idempotent. The workdir is kept.
func (e *Engine) Close() error {
	e.closed.Store(true)
	return nil
}

func (e *Engine) current() (*snapshot, error) {
	if e.closed.Load() {
		return nil, ErrClosed
	}
	if e.cfg.refresh > 0 && time.Since(time.Unix(0, e.lastRefresh.Load())) >= e.cfg.refresh {
		if _, err := e.Refresh(context.Background()); err != nil {
			return nil, err
		}
	}
	return e.snap.Load(), nil
}

// Workdir returns the absolute working folder.
func (e *Engine) Workdir() string { return e.store.Root() }

// Revision identifies the active definitions snapshot.
func (e *Engine) Revision() string { return e.snap.Load().revision }

// Types returns the catalogue, sorted by name.
func (e *Engine) Types() []TypeInfo { return e.snap.Load().catalog.Types() }

// Type returns one type's definition.
func (e *Engine) Type(name string) (TypeInfo, bool) { return e.snap.Load().catalog.Get(name) }

// IsA reports whether child is parent or one of its descendants.
func (e *Engine) IsA(child, parent string) bool { return e.snap.Load().catalog.IsA(child, parent) }

// Catalog returns the active catalogue.
func (e *Engine) Catalog() *catalog.Catalog { return e.snap.Load().catalog }

// Definitions lists installed module names, sorted.
func (e *Engine) Definitions() []string {
	snap := e.snap.Load()
	out := make([]string, 0, len(snap.modules))
	for n := range snap.modules {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Classifiers lists every classifier's spec, sorted by ID.
func (e *Engine) Classifiers() []Spec {
	snap := e.snap.Load()
	out := make([]Spec, len(snap.classifiers))
	for i, ce := range snap.classifiers {
		out[i] = ce.spec
	}
	return out
}

// Classify classifies a source.
func (e *Engine) Classify(ctx context.Context, src Source, opts ...ClassifyOption) (*Result, error) {
	snap, err := e.current()
	if err != nil {
		return nil, err
	}
	return e.classifyWith(ctx, snap, src, opts...)
}

func (e *Engine) classifyWith(ctx context.Context, snap *snapshot, src Source, opts ...ClassifyOption) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cc := classifyConfig{depth: Standard}
	for _, o := range opts {
		if o != nil {
			o(&cc)
		}
	}
	if e.limits.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.limits.Timeout)
		defer cancel()
	}
	c, err := e.materialise(src)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	obs := combine(e.cfg.observer, cc.observer)
	sp := startSpan(obs, nil, "classify", c.digest)
	j := &job{e: e, snap: snap, ctx: ctx, depth: cc.depth, recurse: cc.recurse, limits: e.limits, obs: obs, span: sp}
	res := j.run(c)
	j.close()
	sp.end(nil)
	return finish(snap, res, c.name), nil
}

// finish attaches the name hint and name-dependent anomalies to a shallow
// copy of the root, leaving the shared (cached) result untouched.
func finish(snap *snapshot, r *Result, name string) *Result {
	if name == "" {
		return r
	}
	out := *r
	out.Name = name
	if a := extensionMismatch(snap.catalog, r, name); len(a) > 0 {
		out.Anomalies = appendAnomalies(append([]Anomaly(nil), r.Anomalies...), a...)
		sortAnomalies(out.Anomalies)
	}
	return &out
}

func newReader(c *content, l Limits) *paged.Reader { return paged.New(c.ra, c.size, l.MaxBytes) }

// --- result caches ---

func lruKey(digest, rev string, d Depth, text bool) string {
	return fmt.Sprintf("%s|%s|%s|%t", digest, rev, d, text)
}

func (e *Engine) lruGet(digest, rev string, d Depth, text bool) *Result {
	e.lruMu.Lock()
	defer e.lruMu.Unlock()
	return e.lru[lruKey(digest, rev, d, text)]
}

func (e *Engine) lruPut(digest, rev string, d Depth, text bool, r *Result) {
	k := lruKey(digest, rev, d, text)
	e.lruMu.Lock()
	defer e.lruMu.Unlock()
	if _, ok := e.lru[k]; !ok {
		e.order = append(e.order, k)
		for len(e.order) > lruCapacity {
			delete(e.lru, e.order[0])
			e.order = e.order[1:]
		}
	}
	e.lru[k] = r
}

func (e *Engine) loadNode(digest, rev string, d Depth, text bool) *Result {
	b, ok := e.store.Read(digest, nodeFileName(rev, d, text))
	if !ok {
		return nil
	}
	r, err := decodeDAG(b, digest)
	if err != nil {
		return nil
	}
	return r
}

func (e *Engine) storeNode(r *Result, rev string, d Depth, text bool) {
	if b, err := encodeDAG(r); err == nil {
		_ = e.store.Write(r.Digest, nodeFileName(rev, d, text), b)
	}
}
