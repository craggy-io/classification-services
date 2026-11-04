package classify

import (
	"io/fs"
	"runtime"
	"time"
)

// Limits bounds classification work. Zero fields take the defaults shown.
// Exhausting a limit records a Result limitation, never an error.
type Limits struct {
	MaxBytes        int64         // read budget per classifier run; 64 MiB
	Timeout         time.Duration // per Classify call; none
	Parallel        int           // concurrent classifiers / batch workers; min(4, NumCPU)
	ScriptSteps     uint64        // Starlark steps per run; 4,000,000
	MaxDepth        int           // derivation depth; 8
	MaxChildren     int           // children per node; 10,000
	MaxNodes        int           // derived nodes per Classify; 100,000
	MaxDerivedBytes int64         // total derived bytes per Classify (and per child); 512 MiB
	MaxExpansion    float64       // decompressed/compressed ratio; 1000
	InlineChild     int64         // children above this are spooled to disk; 4 MiB
}

func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = 64 << 20
	}
	if l.Parallel <= 0 {
		l.Parallel = max(1, min(4, runtime.NumCPU()))
	}
	if l.ScriptSteps == 0 {
		l.ScriptSteps = 4_000_000
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 8
	}
	if l.MaxChildren <= 0 {
		l.MaxChildren = 10_000
	}
	if l.MaxNodes <= 0 {
		l.MaxNodes = 100_000
	}
	if l.MaxDerivedBytes <= 0 {
		l.MaxDerivedBytes = 512 << 20
	}
	if l.MaxExpansion <= 0 {
		l.MaxExpansion = 1000
	}
	if l.InlineChild <= 0 {
		l.InlineChild = 4 << 20
	}
	return l
}

type engineConfig struct {
	builtins    bool
	defFS       []fs.FS
	classifiers []Classifier
	limits      Limits
	observer    Observer
	refresh     time.Duration
}

// Option configures Open.
type Option func(*engineConfig)

// WithoutBuiltins omits the built-in catalogue, signatures and classifiers.
// The engine still declares the two roots, "bytes" and "text".
func WithoutBuiltins() Option { return func(c *engineConfig) { c.builtins = false } }

// WithDefinitions adds definition modules (*.star, recursively) shipped by
// an importer. They load after the built-ins; a module with a built-in's
// name replaces it.
func WithDefinitions(fsys fs.FS) Option {
	return func(c *engineConfig) {
		if fsys != nil {
			c.defFS = append(c.defFS, fsys)
		}
	}
}

// WithClassifier registers a native Go classifier.
func WithClassifier(cl Classifier) Option {
	return func(c *engineConfig) {
		if cl != nil {
			c.classifiers = append(c.classifiers, cl)
		}
	}
}

// WithLimits sets the work limits.
func WithLimits(l Limits) Option { return func(c *engineConfig) { c.limits = l } }

// WithObserver receives events for every operation on the engine.
func WithObserver(o Observer) Option { return func(c *engineConfig) { c.observer = o } }

// WithAutoRefresh makes Classify pick up definitions another process
// installed or removed in the workdir, checking at most once per interval.
// Without it, call Refresh explicitly.
func WithAutoRefresh(interval time.Duration) Option {
	return func(c *engineConfig) { c.refresh = interval }
}

type classifyConfig struct {
	depth    Depth
	recurse  func(path []string, c Child) bool
	observer Observer
}

// ClassifyOption configures one Classify call.
type ClassifyOption func(*classifyConfig)

// EffectiveDepth returns the depth Classify would use with base as the
// starting depth and opts applied in order (for callers that report or
// key on the depth a classification actually ran at).
func EffectiveDepth(base Depth, opts ...ClassifyOption) Depth {
	cc := classifyConfig{depth: base}
	for _, o := range opts {
		if o != nil {
			o(&cc)
		}
	}
	return cc.depth
}

// WithDepth sets how far classification goes (Standard by default).
func WithDepth(d Depth) ClassifyOption {
	return func(c *classifyConfig) {
		if d <= Deep {
			c.depth = d
		}
	}
}

// Recurse is consulted before descending into a derived child (whose
// Result carries only Digest and Size at that point). Returning false prunes
// the child. Calls with a filter bypass the whole-result cache, since the
// filter changes the result's shape.
func Recurse(keep func(path []string, c Child) bool) ClassifyOption {
	return func(c *classifyConfig) { c.recurse = keep }
}

// Observe receives events for this call, in addition to any engine observer.
func Observe(o Observer) ClassifyOption { return func(c *classifyConfig) { c.observer = o } }
