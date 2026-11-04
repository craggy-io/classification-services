package views

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// CFB is a parsed Compound File Binary (OLE2) container: legacy Office
// documents, MSI installers, Outlook .msg files.
type CFB struct {
	MajorVersion uint16
	SectorSize   int64
	// Entries lists directory entry names (streams and storages), bounded.
	Entries   []string
	RootCLSID string
	// Kind is a best-effort application guess from well-known stream names:
	// "word", "excel", "powerpoint", "msi", "outlook-msg" or "".
	Kind string
	// Macros is set when a VBA project storage or stream is present.
	Macros bool
}

var cfbMagic = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

const (
	maxCFBDirSectors = 256
	cfbEndOfChain    = 0xfffffffe
)

// Describe implements Describer.
func (c *CFB) Describe() map[string]any {
	return map[string]any{
		"major_version": int64(c.MajorVersion), "sector_size": c.SectorSize,
		"entries": strs(c.Entries), "kind": c.Kind, "macros": c.Macros, "root_clsid": c.RootCLSID,
	}
}

// ParseCFB validates the header and walks the directory chain using the
// FAT sectors listed in the header (the first 109 DIFAT entries, which cover
// files up to roughly 7 MiB with 512-byte sectors and much more with 4 KiB).
func ParseCFB(ra io.ReaderAt, size int64) (*CFB, error) {
	h, err := ReadRange(ra, size, 0, 512)
	if err != nil {
		return nil, err
	}
	if len(h) < 512 || !bytes.Equal(h[:8], cfbMagic) {
		return nil, fmt.Errorf("views: not a compound file")
	}
	le := binary.LittleEndian
	c := &CFB{MajorVersion: le.Uint16(h[26:])}
	shift := le.Uint16(h[30:])
	switch {
	case c.MajorVersion == 3 && shift == 9, c.MajorVersion == 4 && shift == 12:
	default:
		return nil, fmt.Errorf("views: invalid compound file version %d / sector shift %d", c.MajorVersion, shift)
	}
	c.SectorSize = 1 << shift
	sectorOff := func(s uint32) int64 { return (int64(s) + 1) * c.SectorSize }

	var fat []uint32
	for i := 0; i < 109; i++ {
		s := le.Uint32(h[76+4*i:])
		if s >= 0xfffffffa {
			continue
		}
		b, err := readExact(ra, size, sectorOff(s), c.SectorSize)
		if err != nil {
			break
		}
		for j := 0; j+4 <= len(b); j += 4 {
			fat = append(fat, le.Uint32(b[j:]))
		}
	}
	dir := le.Uint32(h[48:])
	names := map[string]bool{}
	for n := 0; dir < cfbEndOfChain && n < maxCFBDirSectors; n++ {
		b, err := readExact(ra, size, sectorOff(dir), c.SectorSize)
		if err != nil {
			return nil, fmt.Errorf("views: compound file directory: %w", err)
		}
		for e := 0; e+128 <= len(b); e += 128 {
			ent := b[e : e+128]
			nameLen := int(le.Uint16(ent[64:]))
			if ent[66] == 0 || nameLen < 2 || nameLen > 64 { // unused entry
				continue
			}
			u := make([]uint16, nameLen/2-1)
			for i := range u {
				u[i] = le.Uint16(ent[2*i:])
			}
			name := string(utf16.Decode(u))
			if ent[66] == 5 && c.RootCLSID == "" {
				c.RootCLSID = fmt.Sprintf("%x", ent[80:96])
			}
			if len(c.Entries) < 512 {
				c.Entries = append(c.Entries, name)
			}
			names[name] = true
		}
		if int64(dir) >= int64(len(fat)) {
			break
		}
		dir = fat[dir]
	}
	switch {
	case names["WordDocument"]:
		c.Kind = "word"
	case names["Workbook"] || names["Book"]:
		c.Kind = "excel"
	case names["PowerPoint Document"]:
		c.Kind = "powerpoint"
	case names["__properties_version1.0"]:
		c.Kind = "outlook-msg"
	}
	for n := range names {
		if n == "VBA" || n == "_VBA_PROJECT_CUR" || n == "Macros" || n == "_VBA_PROJECT" || strings.EqualFold(n, "vbaProject.bin") {
			c.Macros = true
		}
		if c.Kind == "" && strings.HasPrefix(n, "䡀") { // MSI tables use mangled names
			c.Kind = "msi"
		}
	}
	return c, nil
}
