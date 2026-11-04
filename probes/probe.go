// Package probes holds the built-in native recognisers, grouped by format
// family. Each probe declares the types it produces and requires, so the
// whole built-in set is described by Builtins() and the engine only adapts
// its Input to the small contract here.
//
// Probes depend on views and evidence only; the classify engine imports
// probes, never the reverse, so probes are testable and reusable alone.
package probes

import (
	"context"
	"fmt"
	"io"

	"github.com/craggy-io/classification-services/evidence"
)

// Level aliases the shared evidence level.
type Level = evidence.Level

const (
	Candidate  = evidence.Candidate
	Recognised = evidence.Recognised
	Validated  = evidence.Validated
)

// Finding is one probe output: a type assertion or rejection, optionally
// with derived children and anomalies. A Finding with an empty Type carries
// only children and/or anomalies.
type Finding struct {
	Type      string
	Level     Level
	Metadata  map[string]any
	Reject    bool
	Children  []Derived
	Anomalies []evidence.Anomaly
}

// Match builds a type assertion.
func Match(t string, level Level, metadata map[string]any) Finding {
	return Finding{Type: t, Level: level, Metadata: metadata}
}

// Reject refutes lower-evidence assertions of t.
func Reject(t string, level Level) Finding {
	return Finding{Type: t, Level: level, Reject: true}
}

// Derived is content derived from the input: Data bytes, or a byte range of
// the input itself when Length > 0 (no copy is made).
type Derived struct {
	Name        string
	Data        []byte
	Offset      int64
	Length      int64
	Speculative bool
}

// Limits carries the budget values probes honour.
type Limits struct {
	MaxBytes        int64   // read budget for one probe
	MaxDerivedBytes int64   // cap on one derived child
	MaxExpansion    float64 // decompressed/compressed ratio cap
}

// Input is the bounded access probes get to the content.
type Input interface {
	Size() int64
	// Name is the source's file name hint (may be empty).
	Name() string
	Prefix(n int64) ([]byte, error)
	Read(off, n int64) ([]byte, error)
	Text(limit int64) (string, error)
	JSON(limit int64) (any, error)
	// View returns the memoised named view (see package views).
	View(name string) (any, error)
	Reader() io.ReaderAt
	Limits() Limits
}

// Func is the shape of every probe.
type Func func(ctx context.Context, in Input) ([]Finding, error)

// Probe binds a recogniser to its scheduling contract.
type Probe struct {
	ID       string
	Produces []string // types it may assert or reject
	Requires []string // types that must hold before it runs
	Derives  bool     // may emit children
	Run      Func
}

// view fetches a typed view.
func view[T any](in Input, name string) (T, error) {
	var zero T
	v, err := in.View(name)
	if err != nil {
		return zero, err
	}
	t, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("probes: view %q has type %T", name, v)
	}
	return t, nil
}

// expansionLimit is the byte cap for decompressing a payload of
// compressed size n.
func expansionLimit(in Input, n int64) int64 {
	l := in.Limits()
	limit := l.MaxDerivedBytes
	if e := int64(l.MaxExpansion * float64(n)); e > 0 && e < limit {
		limit = e
	}
	return limit
}

// Revision identifies the built-in probe implementations. Bump it when a
// probe's behaviour changes so cached results are recomputed.
const Revision = "probes-v1"

// Builtins returns every built-in probe.
func Builtins() []Probe {
	return []Probe{
		// text and character sets
		{ID: "text", Produces: []string{"text"}, Requires: []string{"bytes"}, Run: Text},
		{ID: "charset", Produces: []string{"charset.utf8-bom", "charset.utf16le", "charset.utf16be", "charset.utf32le"}, Requires: []string{"bytes"}, Derives: true, Run: Charset},
		{ID: "shebang", Produces: []string{"source.shell", "source.bash", "source.python", "source.perl", "source.ruby", "source.php", "source.node"}, Requires: []string{"text"}, Run: Shebang},
		{ID: "java-source", Produces: []string{"source.java"}, Requires: []string{"text"}, Run: JavaSource},
		// structured data
		{ID: "json", Produces: []string{"data.json"}, Requires: []string{"text"}, Run: JSON},
		{ID: "xml", Produces: []string{"data.xml", "data.plist-xml", "image.svg"}, Requires: []string{"text"}, Run: XML},
		{ID: "sqlite", Produces: []string{"data.sqlite"}, Requires: []string{"bytes"}, Run: SQLite},
		// encodings
		{ID: "base64", Produces: []string{"encoding.base64"}, Requires: []string{"text"}, Run: Base64},
		{ID: "base64-decode", Requires: []string{"encoding.base64"}, Derives: true, Run: Base64Decode},
		{ID: "hex", Produces: []string{"encoding.hex"}, Requires: []string{"text"}, Run: Hex},
		{ID: "hex-decode", Requires: []string{"encoding.hex"}, Derives: true, Run: HexDecode},
		{ID: "digest", Produces: []string{"crypto.digest"}, Requires: []string{"text"}, Run: Digest},
		// archives
		{ID: "zip", Produces: []string{"archive.zip"}, Requires: []string{"bytes"}, Derives: true, Run: ZIP},
		{ID: "zip-entries", Requires: []string{"archive.zip"}, Derives: true, Run: ZIPEntries},
		{ID: "tar", Produces: []string{"archive.tar"}, Requires: []string{"bytes"}, Run: Tar},
		{ID: "tar-entries", Requires: []string{"archive.tar"}, Derives: true, Run: TarEntries},
		{ID: "ar", Produces: []string{"archive.ar", "archive.deb"}, Requires: []string{"bytes"}, Derives: true, Run: Ar},
		{ID: "cpio", Produces: []string{"archive.cpio"}, Requires: []string{"bytes"}, Run: Cpio},
		{ID: "rpm", Produces: []string{"archive.rpm"}, Requires: []string{"bytes"}, Run: RPM},
		// compression
		{ID: "gzip", Produces: []string{"compression.gzip"}, Requires: []string{"bytes"}, Derives: true, Run: Gzip},
		{ID: "bzip2", Produces: []string{"compression.bzip2"}, Requires: []string{"bytes"}, Derives: true, Run: Bzip2},
		{ID: "zlib", Produces: []string{"compression.zlib"}, Requires: []string{"bytes"}, Derives: true, Run: Zlib},
		{ID: "xz", Produces: []string{"compression.xz"}, Requires: []string{"bytes"}, Run: XZ},
		{ID: "zstd", Produces: []string{"compression.zstd"}, Requires: []string{"bytes"}, Run: Zstd},
		// android
		{ID: "apk", Produces: []string{"android.apk", "android.apk-set", "android.aab"}, Requires: []string{"archive.zip"}, Run: APK},
		{ID: "dex", Produces: []string{"android.dex"}, Requires: []string{"bytes"}, Run: Dex},
		{ID: "axml", Produces: []string{"android.axml"}, Requires: []string{"bytes"}, Run: AXML},
		// executables
		{ID: "elf", Produces: []string{"executable.elf", "executable.elf-shared-object"}, Requires: []string{"bytes"}, Derives: true, Run: ELF},
		{ID: "pe", Produces: []string{"executable.pe", "executable.pe-dll", "executable.dotnet", "executable.dos-mz"}, Requires: []string{"bytes"}, Derives: true, Run: PE},
		{ID: "macho", Produces: []string{"executable.macho", "executable.macho-universal"}, Requires: []string{"bytes"}, Run: MachO},
		{ID: "java-class", Produces: []string{"executable.java-class"}, Requires: []string{"bytes"}, Run: JavaClass},
		// documents
		{ID: "pdf", Produces: []string{"document.pdf"}, Requires: []string{"bytes"}, Run: PDF},
		{ID: "office-zip", Produces: []string{"document.ooxml", "document.docx", "document.xlsx", "document.pptx", "document.odf", "document.epub"}, Requires: []string{"archive.zip"}, Run: OfficeZip},
		{ID: "cfb", Produces: []string{"document.ole2", "document.doc", "document.xls", "document.ppt", "executable.msi", "data.outlook-msg"}, Requires: []string{"bytes"}, Run: CFB},
		// images, network, crypto
		{ID: "png", Produces: []string{"image.png"}, Requires: []string{"bytes"}, Run: PNG},
		{ID: "pcap", Produces: []string{"network.pcap", "network.pcapng"}, Requires: []string{"bytes"}, Run: Pcap},
		{ID: "pem", Produces: []string{"crypto.pem", "crypto.x509", "crypto.private-key"}, Requires: []string{"text"}, Derives: true, Run: PEM},
		{ID: "der-certificate", Produces: []string{"crypto.x509"}, Requires: []string{"bytes"}, Run: DERCertificate},
		{ID: "jwt", Produces: []string{"crypto.jwt"}, Requires: []string{"text"}, Run: JWT},
	}
}
