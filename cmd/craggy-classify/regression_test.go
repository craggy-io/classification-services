package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseDoubleDashTerminatesFlags(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var c common
	c.register(fs)
	fs.Bool("tree", false, "")
	pos, err := parse(fs, []string{"--", "a.json", "--tree"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pos, []string{"a.json", "--tree"}) {
		t.Fatalf("pos = %v", pos)
	}
}

func TestHelpExitsZeroAndJSONErrors(t *testing.T) {
	wd := t.TempDir()
	if code, _, _ := cli(t, wd, "--help"); code != exitOK {
		t.Fatalf("--help exit = %d", code)
	}
	if code, _, _ := cli(t, wd, "types", "a", "b"); code != exitError {
		t.Fatalf("types with extra arg exit = %d", code)
	}
	code, out, _ := cli(t, wd, "--json", filepath.Join(wd, "missing.bin"))
	if code != exitError || !strings.Contains(out, `"error"`) || !strings.Contains(out, "missing.bin") {
		t.Fatalf("json missing file: code=%d out=%q", code, out)
	}
}

func TestExitCodePrecedenceStable(t *testing.T) {
	wd := t.TempDir()
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "a.zip")
	os.WriteFile(zipPath, []byte(`{"not":"a zip"}`), 0o644) // extension-mismatch warning
	missing := filepath.Join(dir, "missing.bin")
	// Both orders: an I/O error (1) beats the --fail-on anomaly (2).
	for _, args := range [][]string{{zipPath, missing}, {missing, zipPath}} {
		code, _, _ := cli(t, wd, append(args, "--fail-on", "warning")...)
		if code != exitError {
			t.Fatalf("args %v: exit = %d, want %d", args, code, exitError)
		}
	}
}
