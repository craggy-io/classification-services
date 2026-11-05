// Command craggy-classify classifies files and manages definitions from the
// shell. Output is human-readable by default and JSON (one object per line)
// with --json, so agents and scripts can consume it.
//
//	craggy-classify [classify] [flags] PATH...   classify files (directories are walked)
//	craggy-classify types [--json] [PREFIX]      list catalogue types
//	craggy-classify check BUNDLE[#ID]               validate modules and run their tests
//	craggy-classify preview BUNDLE[#ID] [PATH...]   show what the modules would change
//	craggy-classify define BUNDLE[#ID]              test and install the modules
//	craggy-classify remove NAME                  uninstall a module
//	craggy-classify definitions                  list installed modules
//	craggy-classify test                         run every installed module's tests
//	craggy-classify maintain                     prune the cache
//
// BUNDLE is a directory with a bundle.yaml. Without #ID, every
// classify.module@1 contribution in it is used; with #ID, only that one.
// Module names are contribution IDs.
//
// The workdir defaults to $CRAGGY_CLASSIFY_WORKDIR, else
// <user cache dir>/craggy/classification.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"github.com/craggy-io/foundation-kit/bundle"

	"github.com/craggy-io/classification-services/classify"
	"github.com/craggy-io/classification-services/definitions"
	"github.com/craggy-io/classification-services/evidence"
	"github.com/craggy-io/classification-services/signatures"
)

// Exit codes.
const (
	exitOK      = 0
	exitError   = 1 // usage, I/O or definition errors; failed tests
	exitAnomaly = 2 // an anomaly at or above --fail-on was reported
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

type common struct {
	workdir string
	json    bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.workdir, "workdir", defaultWorkdir(), "cache and definitions folder")
	fs.BoolVar(&c.json, "json", false, "write JSON (one object per line)")
}

func defaultWorkdir() string {
	if d := os.Getenv("CRAGGY_CLASSIFY_WORKDIR"); d != "" {
		return d
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "craggy", "classification")
	}
	return ".craggy-classify"
}

// parse accepts flags before, between and after positional arguments.
// A "--" argument ends flag parsing for good: everything after it is
// positional, even if it looks like a flag.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var tail []string
	for i, a := range args {
		if a == "--" {
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return append(pos, tail...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

var commands = map[string]bool{
	"classify": true, "types": true, "check": true, "preview": true, "define": true,
	"remove": true, "definitions": true, "test": true, "maintain": true, "help": true,
}

// valueFlags take a separate value argument ("--workdir DIR").
var valueFlags = map[string]bool{"workdir": true, "depth": true, "fail-on": true, "explain": true, "name": true}

// command finds the subcommand: the first positional argument, when it names
// one. Flags may precede it.
func command(args []string) (string, []string) {
	classifyFlag := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			name := strings.TrimLeft(a, "-")
			if n, _, _ := strings.Cut(name, "="); n == "depth" || n == "fail-on" || n == "explain" || n == "tree" {
				classifyFlag = true
			}
			if valueFlags[name] && !strings.Contains(name, "=") {
				i++
			}
			continue
		}
		if commands[a] {
			// With classify flags before it, an existing file that happens
			// to be named like a command is a path, not a subcommand.
			// (Use ./test to classify a file named "test" otherwise.)
			if classifyFlag {
				if fi, err := os.Stat(a); err == nil && fi.Mode().IsRegular() {
					break
				}
			}
			return a, append(append([]string(nil), args[:i]...), args[i+1:]...)
		}
		break
	}
	return "classify", args
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd, args := command(args)
	if cmd == "help" {
		fmt.Fprintln(stdout, usage)
		return exitOK
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, usage) }
	var c common
	c.register(fs)
	var depth, failOn, explain string
	var tree bool
	switch cmd {
	case "classify":
		fs.StringVar(&depth, "depth", "standard", "quick, standard or deep")
		fs.StringVar(&failOn, "fail-on", "", "exit 2 if an anomaly of this severity or higher is reported (info, warning, critical)")
		fs.StringVar(&explain, "explain", "", "explain why TYPE holds (or was rejected)")
		fs.BoolVar(&tree, "tree", false, "print derived children")
	}
	pos, err := parse(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	arity := func(want string, ok bool) bool {
		if ok {
			return true
		}
		fmt.Fprintf(stderr, "craggy-classify %s: want %s, got %d argument(s)\n", cmd, want, len(pos))
		return false
	}
	e, err := classify.Open(ctx, c.workdir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	defer e.Close()
	out := &printer{w: stdout, json: c.json}

	switch cmd {
	case "classify":
		if len(pos) == 0 {
			fmt.Fprintln(stderr, "craggy-classify: no paths given (see craggy-classify help)")
			return exitError
		}
		d, err := classify.ParseDepth(depth)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		threshold := evidence.Severity(255)
		if failOn != "" {
			if threshold, err = evidence.ParseSeverity(failOn); err != nil {
				fmt.Fprintln(stderr, err)
				return exitError
			}
		}
		return classifyPaths(ctx, e, pos, d, threshold, explain, tree, out, stderr)
	case "types":
		if !arity("at most one PREFIX", len(pos) <= 1) {
			return exitError
		}
		prefix := ""
		if len(pos) > 0 {
			prefix = pos[0]
		}
		for _, t := range e.Types() {
			if strings.HasPrefix(t.Name, prefix) {
				out.typeInfo(t)
			}
		}
		return exitOK
	case "definitions":
		if !arity("no arguments", len(pos) == 0) {
			return exitError
		}
		for _, d := range e.Definitions() {
			out.line(d, map[string]any{"module": d})
		}
		return exitOK
	case "check", "define", "preview":
		if cmd != "preview" && !arity("exactly one BUNDLE[#ID]", len(pos) == 1) {
			return exitError
		}
		if len(pos) == 0 {
			fmt.Fprintf(stderr, "craggy-classify %s: missing BUNDLE[#ID]\n", cmd)
			return exitError
		}
		mods, err := bundleModules(ctx, pos[0])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		switch cmd {
		case "check":
			reps, err := e.CheckModules(ctx, mods...)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return exitError
			}
			failed := false
			for _, rep := range reps {
				out.check(rep)
				failed = failed || !rep.Passed()
			}
			if failed {
				return exitError
			}
		case "define":
			reps, err := e.DefineModules(ctx, mods...)
			for _, rep := range reps {
				out.check(rep)
			}
			if err != nil {
				fmt.Fprintln(stderr, err)
				return exitError
			}
		case "preview":
			var sources []classify.Source
			for _, p := range pos[1:] {
				sources = append(sources, classify.File(p))
			}
			rep, err := e.PreviewModules(ctx, mods, sources...)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return exitError
			}
			out.preview(rep)
		}
		return exitOK
	case "remove":
		if len(pos) != 1 {
			fmt.Fprintln(stderr, "craggy-classify remove: want exactly one module name")
			return exitError
		}
		if err := e.Remove(ctx, pos[0]); err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		return exitOK
	case "test":
		if !arity("no arguments", len(pos) == 0) {
			return exitError
		}
		res, err := e.Test(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		return out.tests(res)
	case "maintain":
		if !arity("no arguments", len(pos) == 0) {
			return exitError
		}
		rep, err := e.Maintain(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		out.line(fmt.Sprintf("removed %d results, %d stat entries, %d spool and %d temp files; kept %d results",
			rep.ResultsRemoved, rep.StatRemoved, rep.SpoolRemoved, rep.TempRemoved, rep.ResultsKept), rep)
		return exitOK
	}
	return exitError
}

func classifyPaths(ctx context.Context, e *classify.Engine, paths []string, d classify.Depth, threshold evidence.Severity, explain string, tree bool, out *printer, stderr io.Writer) int {
	// One documented precedence regardless of order: an error (1) beats
	// an anomaly at --fail-on (2).
	sawError, sawAnomaly := false, false
	report := func(path string, r *classify.Result, err error) error {
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", path, err)
			if out.json {
				out.emit(map[string]any{"path": path, "error": err.Error()})
			}
			sawError = true
			return nil
		}
		out.result(path, r, explain, tree)
		if sev, ok := r.MaxSeverity(); ok && sev >= threshold {
			sawAnomaly = true
		}
		return nil
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			report(p, nil, err)
			continue
		}
		if !fi.IsDir() {
			r, err := e.Classify(ctx, classify.File(p), classify.WithDepth(d))
			report(p, r, err)
			continue
		}
		// Results from parallel workers arrive in any order; sort per directory.
		type item struct {
			path string
			r    *classify.Result
			err  error
		}
		var items []item
		err = e.ClassifyDir(ctx, p, func(path string, r *classify.Result, err error) error {
			items = append(items, item{path, r, err})
			return nil
		}, classify.WithDepth(d))
		sort.Slice(items, func(i, j int) bool { return items[i].path < items[j].path })
		for _, it := range items {
			report(it.path, it.r, it.err)
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			report(p, nil, err)
		}
	}
	switch {
	case sawError:
		return exitError
	case sawAnomaly:
		return exitAnomaly
	}
	return exitOK
}

const usage = `usage: craggy-classify [command] [flags] [args]

commands:
  classify PATH...        classify files; directories are walked (default command)
      --depth quick|standard|deep   --tree   --explain TYPE   --fail-on SEVERITY
  types [PREFIX]          list catalogue types
  check BUNDLE[#ID]       validate modules and run their inline tests
  preview BUNDLE[#ID] [PATH...]   show what the modules would change (default: known files)
  define BUNDLE[#ID]      test and install the modules into the workdir
  remove NAME             uninstall a module
  definitions             list installed modules
  test                    run every installed module's inline tests
  maintain                prune cache entries no definition can use

BUNDLE is a directory with a bundle.yaml listing its modules as
classify.module@1 contributions; module names are their contribution IDs.
Without #ID every module in the bundle is used, with #ID only that one.

common flags:
  --workdir DIR           default $CRAGGY_CLASSIFY_WORKDIR or <user cache>/craggy/classification
  --json                  JSON output, one object per line

exit status: 0 ok, 1 error or failed test, 2 anomaly at or above --fail-on (1 wins when both occur)
a file named like a command is classified when written as ./test, or after classify flags`

// bundleModules loads the bundle named by arg, "DIR" or "DIR#ID", through
// bundle.Load, and returns its classify.module@1 contributions (or just
// ID's) as module sources named by contribution ID.
func bundleModules(ctx context.Context, arg string) ([]classify.ModuleSource, error) {
	dir, id, selected := arg, "", false
	if i := strings.LastIndex(arg, "#"); i >= 0 {
		dir, id, selected = arg[:i], arg[i+1:], true
	}
	if _, err := os.Stat(filepath.Join(dir, "bundle.yaml")); err != nil {
		return nil, fmt.Errorf("craggy-classify: %s is not a bundle: a definitions folder needs a bundle.yaml listing its modules (%w)", dir, err)
	}
	cat, err := bundle.Load(ctx, bundle.Options{
		Sources: []bundle.Source{bundle.Dir(dir)},
		Compilers: []bundle.AnyCompiler{
			bundle.Compile(definitions.ModuleKind, definitions.Compile),
			bundle.Compile(signatures.CyberChefKind, signatures.CompileCyberChef),
		},
	})
	if err != nil {
		return nil, describeLoadError(err)
	}
	var mods []classify.ModuleSource
	for _, d := range bundle.All(cat, definitions.ModuleKind) {
		if !selected || d.Ref.ID == id {
			mods = append(mods, classify.ModuleSource{Name: d.Value.Name, Source: d.Value.Source})
		}
	}
	switch {
	case selected && len(mods) == 0:
		return nil, fmt.Errorf("craggy-classify: bundle %s has no %s contribution %q", dir, definitions.ModuleKind.ID(), id)
	case len(mods) == 0:
		return nil, fmt.Errorf("craggy-classify: bundle %s has no %s contributions", dir, definitions.ModuleKind.ID())
	}
	return mods, nil
}

// describeLoadError lists every diagnostic of a *bundle.LoadError, one per
// line with its file and line.
func describeLoadError(err error) error {
	var le *bundle.LoadError
	if !errors.As(err, &le) {
		return err
	}
	var b strings.Builder
	for _, d := range le.Diagnostics {
		where := d.Path
		if d.Line > 0 {
			where = fmt.Sprintf("%s:%d:%d", d.Path, d.Line, d.Column)
		}
		fmt.Fprintf(&b, "\n  %s: %s: %s", where, d.Code, d.Message)
	}
	return fmt.Errorf("%w%s", err, b.String())
}
