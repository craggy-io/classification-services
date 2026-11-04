package views

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"path"
	"strings"
)

// Zip is a parsed ZIP central directory plus the layout facts that matter
// for security review: data before the archive, after it, duplicate names,
// encrypted entries and names that escape the extraction root.
type Zip struct {
	Files   []*ZipEntry
	Comment string

	// EOCDOffset is where the end-of-central-directory record starts.
	EOCDOffset int64
	// PrependedBytes counts bytes before the archive proper (a ZIP appended
	// to an executable or image shows up here).
	PrependedBytes int64
	// TrailingBytes counts bytes after the EOCD record and its comment.
	TrailingBytes int64
	Duplicates    []string // names appearing more than once
	Traversal     []string // names that are absolute or contain ".." segments
	Encrypted     int      // entries with the encryption flag set

	byName map[string]*ZipEntry
}

// ZipEntry is one ZIP entry.
type ZipEntry struct {
	Name           string
	IsDir          bool
	Size           int64 // uncompressed
	CompressedSize int64
	Method         uint16
	CRC32          uint32
	Encrypted      bool
	file           *zip.File
}

// Open opens the entry for reading.
func (e *ZipEntry) Open() (io.ReadCloser, error) { return e.file.Open() }

// DataOffset is where the entry's (possibly compressed) data starts.
func (e *ZipEntry) DataOffset() (int64, error) { return e.file.DataOffset() }

// Read reads up to limit bytes of the decompressed entry.
func (e *ZipEntry) Read(limit int64) ([]byte, error) {
	rc, err := e.file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, max(limit, 0)))
}

// Has reports whether an entry with the exact name exists.
func (z *Zip) Has(name string) bool {
	_, ok := z.byName[name]
	return ok
}

// Get returns the first entry with the exact name.
func (z *Zip) Get(name string) (*ZipEntry, bool) {
	e, ok := z.byName[name]
	return e, ok
}

// Read reads up to limit bytes of the named entry.
func (z *Zip) Read(name string, limit int64) ([]byte, error) {
	e, ok := z.byName[name]
	if !ok {
		return nil, fmt.Errorf("views: zip entry %q not found", name)
	}
	return e.Read(limit)
}

// Names returns all entry names in central-directory order.
func (z *Zip) Names() []string {
	out := make([]string, len(z.Files))
	for i, f := range z.Files {
		out[i] = f.Name
	}
	return out
}

// HasPrefix reports whether any entry name starts with prefix.
func (z *Zip) HasPrefix(prefix string) bool {
	for _, f := range z.Files {
		if strings.HasPrefix(f.Name, prefix) {
			return true
		}
	}
	return false
}

// Describe implements Describer.
func (z *Zip) Describe() map[string]any {
	return map[string]any{
		"entry_count":     int64(len(z.Files)),
		"comment":         z.Comment,
		"prepended_bytes": z.PrependedBytes,
		"trailing_bytes":  z.TrailingBytes,
		"encrypted":       int64(z.Encrypted),
		"duplicates":      strs(z.Duplicates),
		"traversal":       strs(z.Traversal),
	}
}

const (
	eocdSig    = 0x06054b50
	eocdLen    = 22
	maxComment = 0xffff
)

// ParseZip parses the central directory and records layout anomalies.
func ParseZip(ra io.ReaderAt, size int64) (*Zip, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, err
	}
	z := &Zip{Comment: zr.Comment, byName: map[string]*ZipEntry{}}
	seen := map[string]int{}
	for _, f := range zr.File {
		e := &ZipEntry{
			Name: f.Name, IsDir: strings.HasSuffix(f.Name, "/"),
			Size: clampInt64(f.UncompressedSize64), CompressedSize: clampInt64(f.CompressedSize64),
			Method: f.Method, CRC32: f.CRC32, Encrypted: f.Flags&0x1 != 0, file: f,
		}
		z.Files = append(z.Files, e)
		if e.Encrypted {
			z.Encrypted++
		}
		seen[e.Name]++
		if seen[e.Name] == 1 {
			z.byName[e.Name] = e
		} else if seen[e.Name] == 2 {
			z.Duplicates = append(z.Duplicates, e.Name)
		}
		if escapesRoot(e.Name) {
			z.Traversal = append(z.Traversal, e.Name)
		}
	}
	z.layout(ra, size)
	return z, nil
}

// clampInt64 converts a ZIP64 size to int64 without wrapping negative.
func clampInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// EscapesRoot reports whether an archive member name is absolute (POSIX or
// Windows drive/UNC) or escapes the extraction root via ".." segments.
func EscapesRoot(name string) bool { return escapesRoot(name) }

func escapesRoot(name string) bool {
	n := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(n, "/") || (len(n) >= 2 && n[1] == ':') {
		return true
	}
	for _, seg := range strings.Split(path.Clean("x/"+n), "/") {
		if seg == ".." {
			return true
		}
	}
	return slicesContains(strings.Split(n, "/"), "..")
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// layout locates the EOCD record to measure data before and after the
// archive. Failures here leave the counters at zero: archive/zip already
// accepted the archive, so layout is informational.
func (z *Zip) layout(ra io.ReaderAt, size int64) {
	tailLen := min(size, int64(eocdLen+maxComment))
	tail, err := ReadRange(ra, size, size-tailLen, tailLen)
	if err != nil || len(tail) < eocdLen {
		return
	}
	pos := -1
	for i := len(tail) - eocdLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == eocdSig {
			commentLen := int(binary.LittleEndian.Uint16(tail[i+20:]))
			if i+eocdLen+commentLen <= len(tail) {
				pos = i
				break
			}
		}
	}
	if pos < 0 {
		return
	}
	rec := tail[pos:]
	z.EOCDOffset = size - tailLen + int64(pos)
	commentLen := int64(binary.LittleEndian.Uint16(rec[20:]))
	z.TrailingBytes = size - (z.EOCDOffset + eocdLen + commentLen)
	cdSize := int64(binary.LittleEndian.Uint32(rec[12:]))
	cdOffset := int64(binary.LittleEndian.Uint32(rec[16:]))
	if cdOffset == 0xffffffff || cdSize == 0xffffffff {
		return // ZIP64: offsets live in the ZIP64 record; skip the estimate
	}
	cdStart := z.EOCDOffset - cdSize
	if cdStart < 0 {
		return
	}
	if delta := cdStart - cdOffset; delta > 0 {
		z.PrependedBytes = delta
		return
	}
	// Archives written with correct absolute offsets but still preceded by
	// data: the first local header is not at offset zero.
	if len(z.Files) > 0 {
		if off, err := z.Files[0].file.DataOffset(); err == nil {
			head, _ := ReadRange(ra, size, 0, 4)
			if off > 0 && !bytes.Equal(head, []byte("PK\x03\x04")) {
				lowest := off
				for _, f := range z.Files {
					if o, err := f.file.DataOffset(); err == nil {
						lowest = min(lowest, o)
					}
				}
				// Local header is 30 bytes plus name and extra; scan back.
				win, _ := ReadRange(ra, size, max(lowest-0x10000, 0), lowest-max(lowest-0x10000, 0))
				if i := bytes.Index(win, []byte("PK\x03\x04")); i >= 0 {
					z.PrependedBytes = max(lowest-0x10000, 0) + int64(i)
				}
			}
		}
	}
}
