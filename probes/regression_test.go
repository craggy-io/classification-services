package probes_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/craggy-io/classification-services/internal/testkit"
	"github.com/craggy-io/classification-services/probes"
)

// limitInput overrides the probe limits (and, for JSON, decodes only the
// limited prefix like the engine's paged reader).
type limitInput struct {
	memInput
	lim probes.Limits
}

func (m limitInput) Limits() probes.Limits { return m.lim }
func (m limitInput) JSON(limit int64) (any, error) {
	b, _ := m.Prefix(limit)
	dec := json.NewDecoder(bytes.NewReader(b))
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

func runLim(t *testing.T, fn probes.Func, data []byte, lim probes.Limits) []probes.Finding {
	t.Helper()
	fs, err := fn(context.Background(), limitInput{memInput{data: data}, lim})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestXMLTrailingJunkNotValidated(t *testing.T) {
	if fs := run(t, probes.XML, []byte("<a/>junk")); !rejects(fs, "data.xml") {
		t.Fatalf("findings = %+v", fs)
	}
	if fs := run(t, probes.XML, []byte("<a>&nbsp;</a>")); len(fs) != 0 {
		// &nbsp; is undefined in XML; an error path with a root rejects.
		if f, ok := has(fs, "data.xml"); ok && f.Level == probes.Validated {
			t.Fatalf("HTML entity validated as XML: %+v", fs)
		}
	}
}

func TestJSONPrefixOnlyRecognised(t *testing.T) {
	lim := probes.Limits{MaxBytes: 4, MaxDerivedBytes: 1 << 20, MaxExpansion: 1000}
	data := []byte("{}  not json") // valid in the 4-byte prefix, junk after
	fs := runLim(t, probes.JSON, data, lim)
	f, ok := has(fs, "data.json")
	if !ok || f.Level != probes.Recognised {
		t.Fatalf("findings = %+v, want data.json@recognised", fs)
	}
}

func TestJWTGarbageSignatureRejected(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoieCJ9.!!!garbage!!!"
	if fs := run(t, probes.JWT, []byte(jwt)); len(fs) != 0 {
		t.Fatalf("findings = %+v", fs)
	}
	notJSON := "eyJhbGciOiJIUzI1NiJ9.bm90LWpzb24.c2ln" // payload decodes to "not-json"
	if fs := run(t, probes.JWT, []byte(notJSON)); len(fs) != 0 {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestStoredZIPEntryTooLargeFlagged(t *testing.T) {
	z := testkit.Zip(testkit.File{Name: "big.bin", Data: []byte(strings.Repeat("x", 5000)), Store: true})
	lim := probes.Limits{MaxBytes: 64 << 20, MaxDerivedBytes: 100, MaxExpansion: 1000}
	fs := runLim(t, probes.ZIPEntries, z, lim)
	if len(children(fs)) != 0 || !anomaly(fs, "zip.entry-too-large") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestTarWindowsAbsoluteTraversal(t *testing.T) {
	arc := testkit.Tar(testkit.File{Name: `C:\evil\pwn`, Data: []byte("x")})
	fs := run(t, probes.TarEntries, arc)
	if !anomaly(fs, "tar.path-traversal") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestTextZeroMaxBytes(t *testing.T) {
	lim := probes.Limits{MaxBytes: 0}
	if fs := runLim(t, probes.Text, []byte{0x00, 0xff, 0x01}, lim); len(fs) != 0 {
		t.Fatalf("findings = %+v", fs)
	}
}
