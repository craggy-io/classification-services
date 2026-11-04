// Command craggy-classify classifies files and manages definitions from the
// shell. Output is human-readable by default and JSON (one object per line)
// with --json, so agents and scripts can consume it.
//
//	craggy-classify [classify] [flags] PATH...   classify files (directories are walked)
//	craggy-classify types [--json] [PREFIX]      list catalogue types
//	craggy-classify check FILE.star              validate a module and run its tests
//	craggy-classify preview FILE.star [PATH...]  show what a module would change
//	craggy-classify define FILE.star             test and install a module
//	craggy-classify remove NAME                  uninstall a module
//	craggy-classify definitions                  list installed modules
//	craggy-classify test                         run every installed module's tests
//	craggy-classify maintain                     prune the cache
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

	"github.com/craggy-io/classification-services/classify"
	"github.com/craggy-io/classification-services/evidence"
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
	var depth, failOn, name, explain string
	var tree bool
	switch cmd {
	case "classify":
		fs.StringVar(&depth, "depth", "standard", "quick, standard or deep")
		fs.StringVar(&failOn, "fail-on", "", "exit 2 if an anomaly of this severity or higher is reported (info, warning, critical)")
		fs.StringVar(&explain, "explain", "", "explain why TYPE holds (or was rejected)")
		fs.BoolVar(&tree, "tree", false, "print derived children")
	case "check", "preview", "define":
		fs.StringVar(&name, "name", "", "module name (default: file name without .star)")
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
		if cmd != "preview" && !arity("exactly one FILE.star", len(pos) == 1) {
			return exitError
		}
		if len(pos) == 0 {
			fmt.Fprintf(stderr, "craggy-classify %s: missing FILE.star\n", cmd)
			return exitError
		}
		src, err := os.ReadFile(pos[0])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(pos[0]), ".star")
		}
		switch cmd {
		case "check":
			rep, err := e.Check(ctx, name, src)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return exitError
			}
			out.check(rep)
			if !rep.Passed() {
				return exitError
			}
		case "define":
			rep, err := e.Define(ctx, name, src)
			if rep != nil {
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
			rep, err := e.Preview(ctx, name, src, sources...)
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
		out.line(fmt.Sprintf("removed %d results, %d programs, %d stat entries, %d spool and %d temp files; kept %d results",
			rep.ResultsRemoved, rep.ProgramsRemoved, rep.StatRemoved, rep.SpoolRemoved, rep.TempRemoved, rep.ResultsKept), rep)
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
  check FILE.star         validate a module and run its inline tests
  preview FILE.star [PATH...]   show what a module would change (default: known files)
  define FILE.star        test and install a module into the workdir
  remove NAME             uninstall a module
  definitions             list installed modules
  test                    run every installed module's inline tests
  maintain                prune cache entries no definition can use

common flags:
  --workdir DIR           default $CRAGGY_CLASSIFY_WORKDIR or <user cache>/craggy/classification
  --json                  JSON output, one object per line

exit status: 0 ok, 1 error or failed test, 2 anomaly at or above --fail-on (1 wins when both occur)
a file named like a command is classified when written as ./test, or after classify flags`
