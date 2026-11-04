package probes

import (
	"bytes"
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/craggy-io/classification-services/evidence"
	"github.com/craggy-io/classification-services/views"
)

var pdfVersionRe = regexp.MustCompile(`%PDF-(\d+\.\d+)`)

// pdfNames maps PDF name objects worth reporting to anomaly codes.
var pdfNames = map[string]struct {
	code string
	sev  evidence.Severity
	msg  string
}{
	"JavaScript":   {"pdf.javascript", evidence.Warning, "the document contains JavaScript"},
	"JS":           {"pdf.javascript", evidence.Warning, "the document contains JavaScript"},
	"OpenAction":   {"pdf.auto-action", evidence.Warning, "the document runs an action when opened"},
	"AA":           {"pdf.auto-action", evidence.Warning, "the document has additional (automatic) actions"},
	"Launch":       {"pdf.launch", evidence.Critical, "the document can launch an external program"},
	"EmbeddedFile": {"pdf.embedded-file", evidence.Warning, "the document embeds files"},
	"XFA":          {"pdf.xfa", evidence.Info, "the document contains an XFA form"},
	"Encrypt":      {"pdf.encrypted", evidence.Info, "the document is encrypted"},
}

const maxPDFScan = 32 << 20

// PDF recognises PDF documents by header and trailer and reports active
// content (JavaScript, automatic actions, launch actions, embedded files),
// including names obfuscated with #xx escapes.
func PDF(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(1024)
	if err != nil {
		return nil, err
	}
	m := pdfVersionRe.FindSubmatchIndex(head)
	if m == nil {
		return nil, nil
	}
	version := string(head[m[2]:m[3]])
	md := map[string]any{"version": version}
	f := Match("document.pdf", Recognised, md)
	if m[0] > 0 {
		f.Anomalies = append(f.Anomalies, evidence.Anomaly{
			Code: "pdf.leading-data", Severity: evidence.Warning,
			Message:  "data precedes the %PDF header (a common polyglot construction)",
			Metadata: map[string]any{"bytes": m[0]},
		})
	}
	data, err := in.Read(0, min(in.Size(), in.Limits().MaxBytes, maxPDFScan))
	if err != nil {
		return nil, err
	}
	tail := data[max(len(data)-2048, 0):]
	if int64(len(data)) >= in.Size() && bytes.Contains(tail, []byte("%%EOF")) {
		f.Level = Validated
	}
	if n := bytes.Count(data, []byte("%%EOF")); n > 1 {
		md["revisions"] = n
	}
	found := map[string]bool{}
	obfuscated := false
	for i := 0; i < len(data); i++ {
		if data[i] != '/' {
			continue
		}
		j := i + 1
		for j < len(data) && isPDFNameChar(data[j]) {
			j++
		}
		raw := data[i+1 : j]
		name := string(raw)
		if bytes.IndexByte(raw, '#') >= 0 {
			name = decodePDFName(raw)
			if _, ok := pdfNames[name]; ok {
				obfuscated = true
			}
		}
		if a, ok := pdfNames[name]; ok && !found[a.code] {
			found[a.code] = true
			f.Anomalies = append(f.Anomalies, evidence.Anomaly{Code: a.code, Severity: a.sev, Message: a.msg})
		}
		i = j - 1
	}
	if obfuscated {
		f.Anomalies = append(f.Anomalies, evidence.Anomaly{
			Code: "pdf.obfuscated-name", Severity: evidence.Critical,
			Message: "security-relevant PDF names are hidden with #xx escapes",
		})
	}
	sort.Slice(f.Anomalies, func(a, b int) bool { return f.Anomalies[a].Code < f.Anomalies[b].Code })
	return []Finding{f}, nil
}

func isPDFNameChar(c byte) bool {
	if c <= ' ' || c > '~' {
		return false
	}
	return !strings.ContainsRune("()<>[]{}/%", rune(c))
}

func decodePDFName(raw []byte) string {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '#' && i+2 < len(raw) && isHex(raw[i+1]) && isHex(raw[i+2]) {
			b.WriteByte(unhex(raw[i+1])<<4 | unhex(raw[i+2]))
			i += 2
			continue
		}
		b.WriteByte(raw[i])
	}
	return b.String()
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// OfficeZip recognises ZIP-based document formats: Office Open XML
// (docx/xlsx/pptx), OpenDocument and EPUB, and reports VBA macros.
func OfficeZip(_ context.Context, in Input) ([]Finding, error) {
	z, err := view[*views.Zip](in, "zip")
	if err != nil {
		return nil, nil
	}
	if mt, err := z.Read("mimetype", 256); err == nil {
		s := strings.TrimSpace(string(mt))
		switch {
		case s == "application/epub+zip":
			return []Finding{Match("document.epub", Validated, map[string]any{"mimetype": s})}, nil
		case strings.HasPrefix(s, "application/vnd.oasis.opendocument."):
			return []Finding{Match("document.odf", Validated, map[string]any{"mimetype": s})}, nil
		}
	}
	if !z.Has("[Content_Types].xml") {
		return nil, nil
	}
	var out []Finding
	md := map[string]any{}
	f := Match("document.ooxml", Validated, md)
	switch {
	case z.HasPrefix("word/"):
		md["application"] = "word"
		out = append(out, Match("document.docx", Validated, nil))
	case z.HasPrefix("xl/"):
		md["application"] = "excel"
		out = append(out, Match("document.xlsx", Validated, nil))
	case z.HasPrefix("ppt/"):
		md["application"] = "powerpoint"
		out = append(out, Match("document.pptx", Validated, nil))
	default:
		f.Level = Recognised
	}
	for _, e := range z.Files {
		if strings.HasSuffix(strings.ToLower(e.Name), "vbaproject.bin") {
			md["macros"] = true
			f.Anomalies = append(f.Anomalies, evidence.Anomaly{
				Code: "document.macros", Severity: evidence.Warning,
				Message:  "the document carries a VBA project",
				Metadata: map[string]any{"entry": e.Name},
			})
			break
		}
	}
	return append([]Finding{f}, out...), nil
}

// CFB recognises Compound File Binary (OLE2) containers and the legacy
// Office, MSI and Outlook formats built on them, and reports VBA macros.
func CFB(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(8)
	if err != nil || len(head) < 8 || head[0] != 0xd0 || head[1] != 0xcf {
		return nil, err
	}
	c, err := view[*views.CFB](in, "cfb")
	if err != nil {
		return []Finding{Reject("document.ole2", Validated)}, nil
	}
	f := Match("document.ole2", Validated, c.Describe())
	if c.Incomplete {
		f.Anomalies = append(f.Anomalies, evidence.Anomaly{
			Code: "cfb.directory-truncated", Severity: evidence.Warning,
			Message: "the compound file directory could not be read in full; storages may be missing",
		})
	}
	if c.Macros {
		f.Anomalies = append(f.Anomalies, evidence.Anomaly{
			Code: "document.macros", Severity: evidence.Warning,
			Message: "the compound file carries a VBA project",
		})
	}
	out := []Finding{f}
	if t := map[string]string{
		"word": "document.doc", "excel": "document.xls", "powerpoint": "document.ppt",
		"msi": "executable.msi", "outlook-msg": "data.outlook-msg",
	}[c.Kind]; t != "" {
		out = append(out, Match(t, Validated, nil))
	}
	return out, nil
}
