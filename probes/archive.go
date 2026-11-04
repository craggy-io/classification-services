package probes

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/craggy-io/classification-services/evidence"
	"github.com/craggy-io/classification-services/views"
)

// ZIP validates the central directory and reports layout anomalies: data
// before the archive (derived as a child, so a stub executable or image is
// classified too), trailing data, duplicate names, encrypted entries and
// names that escape the extraction root.
func ZIP(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(4)
	if err != nil {
		return nil, err
	}
	z, err := view[*views.Zip](in, "zip")
	if err != nil {
		if bytes.HasPrefix(head, []byte("PK")) {
			return []Finding{Reject("archive.zip", Validated)}, nil
		}
		return nil, nil
	}
	names := z.Names()
	if len(names) > 1000 {
		names = names[:1000]
	}
	md := map[string]any{"entry_count": len(z.Files), "entries": names}
	if z.Comment != "" {
		md["comment"] = z.Comment
	}
	f := Match("archive.zip", Validated, md)
	if z.PrependedBytes > 0 {
		f.Anomalies = append(f.Anomalies, evidence.Anomaly{
			Code: "zip.prepended-data", Severity: evidence.Warning,
			Message:  "data precedes the ZIP archive",
			Metadata: map[string]any{"bytes": z.PrependedBytes},
		})
		f.Children = append(f.Children, Derived{Name: "prepended data", Offset: 0, Length: z.PrependedBytes})
	}
	if z.TrailingBytes > 0 {
		f.Anomalies = append(f.Anomalies, evidence.Anomaly{
			Code: "zip.trailing-data", Severity: evidence.Info,
			Message:  "data follows the ZIP end-of-central-directory record",
			Metadata: map[string]any{"bytes": z.TrailingBytes},
		})
	}
	if len(z.Duplicates) > 0 {
		f.Anomalies = append(f.Anomalies, evidence.Anomaly{
			Code: "zip.duplicate-entry", Severity: evidence.Warning,
			Message:  "entry names appear more than once; extractors disagree on which wins",
			Metadata: map[string]any{"names": first(z.Duplicates, 50)},
		})
	}
	if len(z.Traversal) > 0 {
		f.Anomalies = append(f.Anomalies, evidence.Anomaly{
			Code: "zip.path-traversal", Severity: evidence.Critical,
			Message:  "entry names are absolute or escape the extraction directory",
			Metadata: map[string]any{"names": first(z.Traversal, 50)},
		})
	}
	if z.Encrypted > 0 {
		f.Anomalies = append(f.Anomalies, evidence.Anomaly{
			Code: "zip.encrypted", Severity: evidence.Info,
			Message:  "entries are encrypted and cannot be inspected",
			Metadata: map[string]any{"entries": z.Encrypted},
		})
	}
	return []Finding{f}, nil
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ZIPEntries derives each file entry. Stored entries become byte ranges of
// the archive (no copy); compressed entries are decompressed up to the
// derived-byte and expansion limits.
func ZIPEntries(_ context.Context, in Input) ([]Finding, error) {
	z, err := view[*views.Zip](in, "zip")
	if err != nil {
		return nil, nil
	}
	lim := in.Limits()
	var out Finding
	var skippedLarge, skippedRatio []string
	for _, e := range z.Files {
		if e.IsDir || e.Encrypted {
			continue
		}
		if e.Size > lim.MaxDerivedBytes {
			skippedLarge = append(skippedLarge, e.Name)
			continue
		}
		if e.CompressedSize > 0 && lim.MaxExpansion > 0 && float64(e.Size) > lim.MaxExpansion*float64(e.CompressedSize) {
			skippedRatio = append(skippedRatio, e.Name)
			continue
		}
		if e.Method == 0 && e.Size == e.CompressedSize {
			if off, err := e.DataOffset(); err == nil && off >= 0 && e.Size <= in.Size()-off {
				out.Children = append(out.Children, Derived{Name: e.Name, Offset: off, Length: e.Size})
				continue
			}
		}
		data, err := e.Read(lim.MaxDerivedBytes + 1)
		if err != nil || int64(len(data)) > lim.MaxDerivedBytes {
			continue // corrupt or lying about its size; other entries proceed
		}
		if len(data) == 0 && e.Size == 0 {
			continue
		}
		out.Children = append(out.Children, Derived{Name: e.Name, Data: data})
	}
	if len(skippedRatio) > 0 {
		out.Anomalies = append(out.Anomalies, evidence.Anomaly{
			Code: "zip.expansion-ratio", Severity: evidence.Warning,
			Message:  "entries declare a decompression ratio above MaxExpansion (possible ZIP bomb); not extracted",
			Metadata: map[string]any{"names": first(skippedRatio, 50)},
		})
	}
	if len(skippedLarge) > 0 {
		out.Anomalies = append(out.Anomalies, evidence.Anomaly{
			Code: "zip.entry-too-large", Severity: evidence.Info,
			Message:  "entries exceed MaxDerivedBytes; not extracted",
			Metadata: map[string]any{"names": first(skippedLarge, 50)},
		})
	}
	if len(out.Children) == 0 && len(out.Anomalies) == 0 {
		return nil, nil
	}
	return []Finding{out}, nil
}

// Tar validates the first header block's checksum.
func Tar(_ context.Context, in Input) ([]Finding, error) {
	if in.Size() < 512 {
		return nil, nil
	}
	block, err := in.Prefix(512)
	if err != nil {
		return nil, err
	}
	stored, err := strconv.ParseInt(string(bytes.Trim(block[148:156], " \x00")), 8, 64)
	ustar := bytes.HasPrefix(block[257:265], []byte("ustar"))
	if err != nil {
		if ustar {
			return []Finding{Reject("archive.tar", Validated)}, nil
		}
		return nil, nil
	}
	var sum, signed int64
	for i, c := range block {
		if i >= 148 && i < 156 {
			c = ' '
		}
		sum += int64(c)
		signed += int64(int8(c))
	}
	if sum != stored && signed != stored {
		if ustar {
			return []Finding{Reject("archive.tar", Validated)}, nil
		}
		return nil, nil
	}
	md := map[string]any{}
	if name := string(bytes.TrimRight(block[:100], "\x00")); name != "" {
		md["first_entry"] = name
	}
	if ustar {
		md["format"] = "ustar"
	}
	return []Finding{Match("archive.tar", Validated, md)}, nil
}

type countingReader struct {
	r   io.Reader
	off int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.off += int64(n)
	return n, err
}

const maxTarEntries = 10_000

// TarEntries derives each regular file as a byte range of the archive.
func TarEntries(_ context.Context, in Input) ([]Finding, error) {
	cr := &countingReader{r: io.NewSectionReader(in.Reader(), 0, in.Size())}
	tr := tar.NewReader(cr)
	var out Finding
	var traversal []string
	for n := 0; n < maxTarEntries; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break // a truncated or corrupt tail; keep what was read
		}
		if views.EscapesRoot(h.Name) {
			traversal = append(traversal, h.Name)
		}
		if h.Typeflag != tar.TypeReg || h.Size <= 0 {
			continue
		}
		if cr.off+h.Size > in.Size() {
			break
		}
		out.Children = append(out.Children, Derived{Name: h.Name, Offset: cr.off, Length: h.Size})
	}
	if len(traversal) > 0 {
		out.Anomalies = append(out.Anomalies, evidence.Anomaly{
			Code: "tar.path-traversal", Severity: evidence.Critical,
			Message:  "member names are absolute or escape the extraction directory",
			Metadata: map[string]any{"names": first(traversal, 50)},
		})
	}
	if len(out.Children) == 0 && len(out.Anomalies) == 0 {
		return nil, nil
	}
	return []Finding{out}, nil
}

// Ar validates a Unix ar archive, recognises Debian packages and derives
// members as byte ranges.
func Ar(_ context.Context, in Input) ([]Finding, error) {
	a, err := view[*views.Ar](in, "ar")
	if err != nil {
		head, _ := in.Prefix(8)
		if bytes.Equal(head, []byte("!<arch>\n")) {
			return []Finding{Reject("archive.ar", Validated)}, nil
		}
		return nil, nil
	}
	names := make([]string, len(a.Members))
	f := Match("archive.ar", Validated, map[string]any{"members": len(a.Members)})
	for i, m := range a.Members {
		names[i] = m.Name
		if m.Size > 0 {
			f.Children = append(f.Children, Derived{Name: m.Name, Offset: m.Offset, Length: m.Size})
		}
	}
	f.Metadata["names"] = first(names, 100)
	out := []Finding{f}
	if a.Debian {
		out = append(out, Match("archive.deb", Validated, nil))
	}
	return out, nil
}

// Cpio recognises the newc, crc, odc and binary cpio formats.
func Cpio(_ context.Context, in Input) ([]Finding, error) {
	h, err := in.Prefix(110)
	if err != nil {
		return nil, err
	}
	switch {
	case len(h) >= 110 && (bytes.HasPrefix(h, []byte("070701")) || bytes.HasPrefix(h, []byte("070702"))):
		for i := 6; i < 110; i++ {
			if !isHex(h[i]) {
				return []Finding{Reject("archive.cpio", Validated)}, nil
			}
		}
		format := "newc"
		if h[5] == '2' {
			format = "crc"
		}
		return []Finding{Match("archive.cpio", Validated, map[string]any{"format": format})}, nil
	case len(h) >= 76 && bytes.HasPrefix(h, []byte("070707")):
		return []Finding{Match("archive.cpio", Recognised, map[string]any{"format": "odc"})}, nil
	case len(h) >= 26 && (bytes.HasPrefix(h, []byte{0xc7, 0x71}) || bytes.HasPrefix(h, []byte{0x71, 0xc7})):
		return []Finding{Match("archive.cpio", Candidate, map[string]any{"format": "binary"})}, nil
	}
	return nil, nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// RPM validates an RPM lead and the header magic that follows its
// signature section.
func RPM(_ context.Context, in Input) ([]Finding, error) {
	lead, err := in.Prefix(112)
	if err != nil {
		return nil, err
	}
	if len(lead) < 96 || !bytes.HasPrefix(lead, []byte{0xed, 0xab, 0xee, 0xdb}) {
		return nil, nil
	}
	if lead[4] != 3 && lead[4] != 4 {
		return []Finding{Reject("archive.rpm", Validated)}, nil
	}
	md := map[string]any{"version": int(lead[4]), "name": strings.TrimRight(string(lead[10:76]), "\x00")}
	level := Recognised
	if len(lead) >= 99 && bytes.Equal(lead[96:99], []byte{0x8e, 0xad, 0xe8}) {
		level = Validated // signature header magic
	}
	return []Finding{Match("archive.rpm", level, md)}, nil
}
