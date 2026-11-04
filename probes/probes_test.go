package probes_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/craggy-io/classification-services/internal/testkit"
	"github.com/craggy-io/classification-services/probes"
	"github.com/craggy-io/classification-services/views"
)

// memInput implements probes.Input over a byte slice.
type memInput struct {
	data []byte
	name string
}

func (m memInput) Size() int64         { return int64(len(m.data)) }
func (m memInput) Name() string        { return m.name }
func (m memInput) Reader() io.ReaderAt { return bytes.NewReader(m.data) }
func (m memInput) Prefix(n int64) ([]byte, error) {
	return m.Read(0, n)
}
func (m memInput) Read(off, n int64) ([]byte, error) {
	return views.ReadRange(bytes.NewReader(m.data), int64(len(m.data)), off, n)
}
func (m memInput) Text(limit int64) (string, error) {
	b, err := m.Prefix(limit)
	return string(b), err
}
func (m memInput) JSON(limit int64) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(m.data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, io.ErrUnexpectedEOF
	}
	return v, nil
}
func (m memInput) View(name string) (any, error) {
	p, _ := views.Lookup(name)
	return p(bytes.NewReader(m.data), int64(len(m.data)))
}
func (m memInput) Limits() probes.Limits {
	return probes.Limits{MaxBytes: 64 << 20, MaxDerivedBytes: 64 << 20, MaxExpansion: 1000}
}

func run(t *testing.T, fn probes.Func, data []byte) []probes.Finding {
	t.Helper()
	fs, err := fn(context.Background(), memInput{data: data})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func has(fs []probes.Finding, typ string) (probes.Finding, bool) {
	for _, f := range fs {
		if f.Type == typ && !f.Reject {
			return f, true
		}
	}
	return probes.Finding{}, false
}

func rejects(fs []probes.Finding, typ string) bool {
	return slices.ContainsFunc(fs, func(f probes.Finding) bool { return f.Type == typ && f.Reject })
}

func anomaly(fs []probes.Finding, code string) bool {
	for _, f := range fs {
		for _, a := range f.Anomalies {
			if a.Code == code {
				return true
			}
		}
	}
	return false
}

func children(fs []probes.Finding) []probes.Derived {
	var out []probes.Derived
	for _, f := range fs {
		out = append(out, f.Children...)
	}
	return out
}

// Every type a built-in probe can produce must be in the catalogue; this is
// checked by the classify package. Here: IDs are unique and every probe
// either produces types or derives.
func TestBuiltinsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range probes.Builtins() {
		if seen[p.ID] {
			t.Fatalf("duplicate probe %q", p.ID)
		}
		seen[p.ID] = true
		if len(p.Produces) == 0 && !p.Derives {
			t.Fatalf("probe %q neither produces nor derives", p.ID)
		}
	}
}

func TestTextCharsetShebang(t *testing.T) {
	if _, ok := has(run(t, probes.Text, []byte("plain text\n")), "text"); !ok {
		t.Fatal("text not recognised")
	}
	if _, ok := has(run(t, probes.Text, []byte("bin\x00ary")), "text"); ok {
		t.Fatal("NUL-bearing content called text")
	}
	utf16 := []byte{0xff, 0xfe, 'h', 0, 'i', 0}
	fs := run(t, probes.Charset, utf16)
	if _, ok := has(fs, "charset.utf16le"); !ok || string(children(fs)[0].Data) != "hi" {
		t.Fatalf("UTF-16LE: %+v", fs)
	}
	bomless := []byte("h\x00e\x00l\x00l\x00o\x00 \x00w\x00o\x00r\x00l\x00d\x00!\x00")
	if _, ok := has(run(t, probes.Charset, bomless), "charset.utf16le"); !ok {
		t.Fatal("BOM-less UTF-16LE not recognised")
	}
	for src, want := range map[string]string{
		"#!/bin/sh\necho": "source.shell", "#!/usr/bin/env python3\n": "source.python",
		"#!/usr/bin/env -S node --x\n": "source.node", "#!/bin/bash -e\n": "source.bash",
	} {
		if _, ok := has(run(t, probes.Shebang, []byte(src)), want); !ok {
			t.Fatalf("%q: want %s", src, want)
		}
	}
}

func TestDataFormats(t *testing.T) {
	f, ok := has(run(t, probes.JSON, []byte(`{"b":1,"a":[1,2]}`)), "data.json")
	if !ok || f.Metadata["kind"] != "object" {
		t.Fatalf("JSON: %+v", f)
	}
	if _, ok := has(run(t, probes.JSON, []byte(`{"a":1} trailing`)), "data.json"); ok {
		t.Fatal("JSON with trailing data validated")
	}
	fs := run(t, probes.XML, []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><g/></svg>`))
	if _, ok := has(fs, "image.svg"); !ok {
		t.Fatalf("SVG: %+v", fs)
	}
	if !rejects(run(t, probes.XML, []byte(`<a></a><b/>`)), "data.xml") {
		t.Fatal("two root elements accepted")
	}
}

func TestEncodings(t *testing.T) {
	f, ok := has(run(t, probes.Digest, []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")), "crypto.digest")
	if !ok || f.Metadata["algorithm_guess"] != "sha256" {
		t.Fatalf("digest: %+v", f)
	}
	if _, ok := has(run(t, probes.Base64, []byte("aGVsbG8gd29ybGQsIHRoaXMgaXMgYmFzZTY0")), "encoding.base64"); !ok {
		t.Fatal("base64 not recognised")
	}
	if _, ok := has(run(t, probes.Base64, []byte("this is just a sentence of prose")), "encoding.base64"); ok {
		t.Fatal("prose called base64")
	}
}

func TestArchives(t *testing.T) {
	z := testkit.Zip(testkit.File{Name: "../evil", Data: []byte("x")}, testkit.File{Name: "ok.txt", Data: []byte("stored"), Store: true})
	fs := run(t, probes.ZIP, z)
	if _, ok := has(fs, "archive.zip"); !ok || !anomaly(fs, "zip.path-traversal") {
		t.Fatalf("zip: %+v", fs)
	}
	kids := children(run(t, probes.ZIPEntries, z))
	if len(kids) != 2 {
		t.Fatalf("zip entries: %+v", kids)
	}
	stored := kids[slices.IndexFunc(kids, func(d probes.Derived) bool { return d.Name == "ok.txt" })]
	if stored.Length != 6 || stored.Data != nil || string(z[stored.Offset:stored.Offset+stored.Length]) != "stored" {
		t.Fatalf("stored entry not derived as a range: %+v", stored)
	}
	fs = run(t, probes.ZIP, append(testkit.ELF(256), z...))
	if !anomaly(fs, "zip.prepended-data") || len(children(fs)) != 1 {
		t.Fatalf("prepended: %+v", fs)
	}

	tarData := testkit.Tar(testkit.File{Name: "a.txt", Data: []byte("hello")}, testkit.File{Name: "../b", Data: []byte("x")})
	if _, ok := has(run(t, probes.Tar, tarData), "archive.tar"); !ok {
		t.Fatal("tar not validated")
	}
	fs = run(t, probes.TarEntries, tarData)
	if !anomaly(fs, "tar.path-traversal") || len(children(fs)) != 2 || children(fs)[0].Length != 5 {
		t.Fatalf("tar entries: %+v", fs)
	}
}

func TestCompression(t *testing.T) {
	fs := run(t, probes.Gzip, testkit.Gzip([]byte("payload"), "p.txt"))
	if _, ok := has(fs, "compression.gzip"); !ok || string(children(fs)[0].Data) != "payload" || children(fs)[0].Name != "p.txt" {
		t.Fatalf("gzip: %+v", fs)
	}
	bomb := testkit.Gzip(make([]byte, 8<<20), "")
	fs, _ = probes.Gzip(context.Background(), limitedInput{memInput{data: bomb}})
	if !anomaly(fs, "compression.expansion-limit") || len(children(fs)) != 0 {
		t.Fatalf("gzip bomb: %+v", fs)
	}
	if _, ok := has(run(t, probes.XZ, testkit.XZHeader()), "compression.xz"); !ok {
		t.Fatal("xz header not validated")
	}
}

type limitedInput struct{ memInput }

func (l limitedInput) Limits() probes.Limits {
	return probes.Limits{MaxBytes: 64 << 20, MaxDerivedBytes: 1 << 20, MaxExpansion: 100}
}

func TestExecutables(t *testing.T) {
	fs := run(t, probes.ELF, append(testkit.ELF(256), "PK\x03\x04hidden"...))
	if _, ok := has(fs, "executable.elf"); !ok || !anomaly(fs, "executable.overlay") || children(fs)[0].Offset != 256 {
		t.Fatalf("ELF overlay: %+v", fs)
	}
	fs = run(t, probes.PE, testkit.PE(true, true))
	for _, want := range []string{"executable.pe", "executable.pe-dll", "executable.dotnet"} {
		if _, ok := has(fs, want); !ok {
			t.Fatalf("PE: missing %s in %+v", want, fs)
		}
	}
	fs = run(t, probes.PE, append([]byte("MZ"), make([]byte, 200)...))
	if !rejects(fs, "executable.pe") {
		t.Fatalf("DOS stub: %+v", fs)
	}
	if _, ok := has(fs, "executable.dos-mz"); !ok {
		t.Fatalf("DOS stub: %+v", fs)
	}
	class := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0, 10}
	if _, ok := has(run(t, probes.JavaClass, class), "executable.java-class"); !ok {
		t.Fatal("java class not validated")
	}
	if fs := run(t, probes.MachO, class); len(fs) != 0 {
		t.Fatalf("java class reported as Mach-O: %+v", fs)
	}
}

func TestAndroid(t *testing.T) {
	manifest := testkit.AXML("com.example", true, "android.permission.INTERNET")
	apk := testkit.Zip(testkit.File{Name: "AndroidManifest.xml", Data: manifest}, testkit.File{Name: "classes.dex", Data: []byte("dex\n")})
	fs := run(t, probes.APK, apk)
	f, ok := has(fs, "android.apk")
	if !ok || f.Metadata["package"] != "com.example" || !anomaly(fs, "android.debuggable") || !anomaly(fs, "android.unsigned") {
		t.Fatalf("APK: %+v", fs)
	}
	signed := testkit.WithSigningBlock(apk, 0x7109871a)
	fs = run(t, probes.APK, signed)
	if anomaly(fs, "android.unsigned") {
		t.Fatalf("v2-signed APK reported unsigned: %+v", fs)
	}
	if _, ok := has(run(t, probes.AXML, manifest), "android.axml"); !ok {
		t.Fatal("standalone AXML not recognised")
	}
}

func TestDocuments(t *testing.T) {
	pdf := []byte("%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R /Names << /J#61vaScript 3 0 R >> >>\nendobj\n%%EOF\n")
	fs := run(t, probes.PDF, pdf)
	f, ok := has(fs, "document.pdf")
	if !ok || f.Level != probes.Validated {
		t.Fatalf("PDF: %+v", fs)
	}
	for _, code := range []string{"pdf.auto-action", "pdf.javascript", "pdf.obfuscated-name"} {
		if !anomaly(fs, code) {
			t.Fatalf("PDF: missing %s in %+v", code, fs)
		}
	}
	docm := testkit.Zip(testkit.File{Name: "[Content_Types].xml", Data: []byte("<Types/>")}, testkit.File{Name: "word/document.xml", Data: []byte("<w/>")}, testkit.File{Name: "word/vbaProject.bin", Data: []byte("x")})
	fs = run(t, probes.OfficeZip, docm)
	if _, ok := has(fs, "document.docx"); !ok || !anomaly(fs, "document.macros") {
		t.Fatalf("docm: %+v", fs)
	}
	fs = run(t, probes.CFB, testkit.CFB("Workbook", "_VBA_PROJECT_CUR"))
	if _, ok := has(fs, "document.xls"); !ok || !anomaly(fs, "document.macros") {
		t.Fatalf("xls: %+v", fs)
	}
}

func TestCryptoAndNetwork(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	text := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})...)
	fs := run(t, probes.PEM, text)
	for _, want := range []string{"crypto.pem", "crypto.x509", "crypto.private-key"} {
		if _, ok := has(fs, want); !ok {
			t.Fatalf("PEM: missing %s", want)
		}
	}
	if !anomaly(fs, "crypto.private-key") || len(children(fs)) != 2 {
		t.Fatalf("PEM: %+v", fs)
	}
	if f, ok := has(run(t, probes.DERCertificate, der), "crypto.x509"); !ok || f.Metadata["self_signed"] != true {
		t.Fatalf("DER: %+v", f)
	}
	jwt := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."
	fs = run(t, probes.JWT, []byte(jwt))
	if _, ok := has(fs, "crypto.jwt"); !ok || !anomaly(fs, "crypto.jwt-unsigned") {
		t.Fatalf("JWT: %+v", fs)
	}
	if _, ok := has(run(t, probes.Pcap, testkit.Pcap(2)), "network.pcap"); !ok {
		t.Fatal("pcap not validated")
	}
}

func FuzzProbes(f *testing.F) {
	f.Add(testkit.Zip(testkit.File{Name: "AndroidManifest.xml", Data: testkit.AXML("p", true)}))
	f.Add(testkit.PE(true, false))
	f.Add([]byte("%PDF-1.4 /JS"))
	f.Add(testkit.Gzip([]byte("x"), "n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range probes.Builtins() {
			p.Run(context.Background(), limitedInput{memInput{data: b}})
		}
	})
}
