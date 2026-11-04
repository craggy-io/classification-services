package views

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Ar is a parsed Unix "ar" archive (static libraries, Debian packages).
type Ar struct {
	Members []ArMember
	Debian  bool // first member is "debian-binary"
}

// ArMember is one archive member.
type ArMember struct {
	Name   string
	Offset int64 // data offset
	Size   int64
}

const maxArMembers = 10_000

// Describe implements Describer.
func (a *Ar) Describe() map[string]any {
	names := make([]any, len(a.Members))
	for i, m := range a.Members {
		names[i] = m.Name
	}
	return map[string]any{"members": names, "debian": a.Debian}
}

// ParseAr walks the member headers.
func ParseAr(ra io.ReaderAt, size int64) (*Ar, error) {
	magic, err := ReadRange(ra, size, 0, 8)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(magic, []byte("!<arch>\n")) {
		return nil, fmt.Errorf("views: not an ar archive")
	}
	a := &Ar{}
	off := int64(8)
	for off < size && len(a.Members) < maxArMembers {
		h, err := readExact(ra, size, off, 60)
		if err != nil {
			return nil, fmt.Errorf("views: ar member header at %d: %w", off, err)
		}
		if h[58] != '`' || h[59] != '\n' {
			return nil, fmt.Errorf("views: ar member header at %d has bad terminator", off)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(h[48:58])), 10, 64)
		if err != nil || n < 0 || off+60+n > size {
			return nil, fmt.Errorf("views: ar member at %d has bad size", off)
		}
		name := strings.TrimRight(strings.TrimSpace(string(h[:16])), "/")
		a.Members = append(a.Members, ArMember{Name: name, Offset: off + 60, Size: n})
		off += 60 + n + n%2
	}
	if len(a.Members) == 0 {
		return nil, fmt.Errorf("views: empty ar archive")
	}
	a.Debian = a.Members[0].Name == "debian-binary"
	return a, nil
}
