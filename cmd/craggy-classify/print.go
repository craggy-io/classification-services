package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/craggy-io/classification-services/classify"
)

type printer struct {
	w    io.Writer
	json bool
}

func (p *printer) emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(p.w, `{"error":%q}`+"\n", err.Error())
		return
	}
	fmt.Fprintf(p.w, "%s\n", b)
}

// line prints text, or v as JSON.
func (p *printer) line(text string, v any) {
	if p.json {
		p.emit(v)
		return
	}
	fmt.Fprintln(p.w, text)
}

func (p *printer) typeInfo(t classify.TypeInfo) {
	if p.json {
		p.emit(t)
		return
	}
	var extra []string
	if t.Abstract {
		extra = append(extra, "abstract")
	}
	if len(t.Ext) > 0 {
		extra = append(extra, "."+strings.Join(t.Ext, " ."))
	}
	if t.MIME != "" {
		extra = append(extra, t.MIME)
	}
	fmt.Fprintf(p.w, "%-34s %-40s %s\n", t.Name, strings.Join(t.Parents, ","), strings.Join(extra, "  "))
}

type jsonResult struct {
	Path        string                `json:"path"`
	Result      *classify.Result      `json:"result"`
	Explanation *classify.Explanation `json:"explanation,omitempty"`
}

func (p *printer) result(path string, r *classify.Result, explain string, tree bool) {
	var ex *classify.Explanation
	if explain != "" {
		if e, ok := r.Explain(explain); ok {
			ex = &e
		} else {
			ex = &classify.Explanation{Type: explain}
		}
	}
	if p.json {
		out := r
		if !tree {
			c := *r
			c.Children = nil
			out = &c
		}
		p.emit(jsonResult{Path: path, Result: out, Explanation: ex})
		return
	}
	level := ""
	if m, ok := r.Get(r.Primary); ok {
		level = m.Level.String()
	}
	fmt.Fprintf(p.w, "%s: %s (%s)\n", path, r.Primary, level)
	var direct []string
	for _, m := range r.Matches {
		if m.Direct && m.Type != r.Primary && m.Type != "bytes" {
			direct = append(direct, m.Type)
		}
	}
	if len(direct) > 0 {
		sort.Strings(direct)
		fmt.Fprintf(p.w, "  also: %s\n", strings.Join(direct, ", "))
	}
	p.anomalies("  ", r)
	for _, l := range r.AllLimitations() {
		fmt.Fprintf(p.w, "  limitation: %s\n", l)
	}
	if tree {
		p.children("  ", r, map[*classify.Result]bool{r: true})
	} else if n := len(r.Children); n > 0 {
		fmt.Fprintf(p.w, "  %d derived children (--tree to list)\n", n)
	}
	if ex != nil {
		for _, l := range strings.Split(strings.TrimRight(ex.String(), "\n"), "\n") {
			fmt.Fprintf(p.w, "  %s\n", l)
		}
	}
}

func (p *printer) anomalies(indent string, r *classify.Result) {
	for _, a := range r.Anomalies {
		fmt.Fprintf(p.w, "%s! %s %s: %s\n", indent, a.Severity, a.Code, a.Message)
	}
}

func (p *printer) children(indent string, r *classify.Result, seen map[*classify.Result]bool) {
	for _, c := range r.Children {
		spec := ""
		if c.Speculative {
			spec = " (speculative)"
		}
		fmt.Fprintf(p.w, "%s└ %s -> %s%s\n", indent, c.Name, c.Primary, spec)
		if seen[c.Result] {
			continue // shared node, already listed
		}
		seen[c.Result] = true
		p.anomalies(indent+"    ", c.Result)
		p.children(indent+"  ", c.Result, seen)
	}
}

func (p *printer) check(rep *classify.CheckReport) {
	if p.json {
		p.emit(rep)
		return
	}
	verb := "adds"
	if rep.Replaces {
		verb = "replaces an installed module and adds"
	}
	fmt.Fprintf(p.w, "%s: %s %d types, %d classifiers, %d signatures\n", rep.Module, verb, len(rep.AddedTypes), len(rep.Classifiers), rep.Signatures)
	for label, ts := range map[string][]string{"changed": rep.ChangedTypes, "removed": rep.RemovedTypes} {
		if len(ts) > 0 {
			fmt.Fprintf(p.w, "  %s types: %s\n", label, strings.Join(ts, ", "))
		}
	}
	for _, t := range rep.Tests {
		mark := "ok  "
		if !t.Passed {
			mark = "FAIL"
		}
		fmt.Fprintf(p.w, "  %s %s (primary %s)\n", mark, t.Name, t.Primary)
		for _, f := range t.Failures {
			fmt.Fprintf(p.w, "       %s\n", f)
		}
	}
}

func (p *printer) preview(rep *classify.PreviewReport) {
	if p.json {
		p.emit(rep)
		return
	}
	p.check(rep.Check)
	fmt.Fprintf(p.w, "examined %d files, %d would change\n", rep.Examined, len(rep.Changes))
	for _, c := range rep.Changes {
		fmt.Fprintf(p.w, "  %s: %s -> %s", c.Name, c.PrimaryBefore, c.PrimaryAfter)
		if len(c.AddedTypes) > 0 {
			fmt.Fprintf(p.w, "  +%s", strings.Join(c.AddedTypes, " +"))
		}
		if len(c.RemovedTypes) > 0 {
			fmt.Fprintf(p.w, "  -%s", strings.Join(c.RemovedTypes, " -"))
		}
		if len(c.AddedAnomalies) > 0 {
			fmt.Fprintf(p.w, "  anomalies +%s", strings.Join(c.AddedAnomalies, " +"))
		}
		if len(c.RemovedAnomalies) > 0 {
			fmt.Fprintf(p.w, "  anomalies -%s", strings.Join(c.RemovedAnomalies, " -"))
		}
		fmt.Fprintln(p.w)
	}
	for _, e := range rep.Errors {
		fmt.Fprintf(p.w, "  error: %s\n", e)
	}
}

func (p *printer) tests(res map[string][]classify.TestResult) int {
	mods := make([]string, 0, len(res))
	for m := range res {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	code := exitOK
	for _, m := range mods {
		for _, t := range res[m] {
			if !t.Passed {
				code = exitError
			}
			if p.json {
				p.emit(map[string]any{"module": m, "test": t})
				continue
			}
			mark := "ok  "
			if !t.Passed {
				mark = "FAIL"
			}
			fmt.Fprintf(p.w, "%s %s / %s\n", mark, m, t.Name)
			for _, f := range t.Failures {
				fmt.Fprintf(p.w, "       %s\n", f)
			}
		}
	}
	return code
}
