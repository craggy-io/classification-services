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
	var nameTable []byte // GNU "//" long-name string table
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
		rawName := strings.TrimSpace(string(h[:16]))
		name := strings.TrimRight(rawName, "/")
		dataOff, dataSize := off+60, n
		switch {
		case rawName == "//" && dataSize <= 16<<20:
			b, err := readExact(ra, size, dataOff, dataSize)
			if err != nil {
				return nil, fmt.Errorf("views: ar name table at %d: %w", off, err)
			}
			nameTable = b
			name = "//"
		case strings.HasPrefix(rawName, "#1/"):
			// BSD extended name: the first len bytes of the data are the name.
			ln, err := strconv.ParseInt(strings.TrimSpace(rawName[3:]), 10, 64)
			if err != nil || ln < 0 || ln > dataSize {
				return nil, fmt.Errorf("views: ar member at %d has bad BSD name length", off)
			}
			nb, err := readExact(ra, size, dataOff, ln)
			if err != nil {
				return nil, fmt.Errorf("views: ar BSD name at %d: %w", off, err)
			}
			name, dataOff, dataSize = string(nb), dataOff+ln, dataSize-ln
		case len(rawName) > 1 && rawName[0] == '/' && nameTable != nil:
			// GNU long name: "/offset" into the string table.
			if noff, err := strconv.ParseInt(strings.TrimSpace(rawName[1:]), 10, 64); err == nil && noff >= 0 && noff < int64(len(nameTable)) {
				end := int(noff)
				for end < len(nameTable) && nameTable[end] != '\n' {
					end++
				}
				name = strings.TrimRight(string(nameTable[noff:end]), "/")
			}
		}
		a.Members = append(a.Members, ArMember{Name: name, Offset: dataOff, Size: dataSize})
		off += 60 + n + n%2
	}
	if len(a.Members) == 0 {
		return nil, fmt.Errorf("views: empty ar archive")
	}
	a.Debian = a.Members[0].Name == "debian-binary"
	return a, nil
}
