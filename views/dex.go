package views

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Dex is a parsed Dalvik Executable header.
type Dex struct {
	Version     string
	FileSize    uint32
	HeaderSize  uint32
	StringCount uint32
	TypeCount   uint32
	ProtoCount  uint32
	FieldCount  uint32
	MethodCount uint32
	ClassCount  uint32
}

// Describe implements Describer.
func (d *Dex) Describe() map[string]any {
	return map[string]any{
		"version": d.Version, "file_size": int64(d.FileSize), "header_size": int64(d.HeaderSize),
		"string_count": int64(d.StringCount), "type_count": int64(d.TypeCount),
		"proto_count": int64(d.ProtoCount), "field_count": int64(d.FieldCount),
		"method_count": int64(d.MethodCount), "class_count": int64(d.ClassCount),
	}
}

// ParseDex parses and validates a DEX header.
func ParseDex(ra io.ReaderAt, size int64) (*Dex, error) {
	hdr, err := ReadRange(ra, size, 0, 112)
	if err != nil {
		return nil, err
	}
	if len(hdr) < 112 {
		return nil, fmt.Errorf("views: truncated DEX header")
	}
	if !bytes.HasPrefix(hdr, []byte("dex\n")) || hdr[7] != 0 {
		return nil, fmt.Errorf("views: not a DEX file")
	}
	ver := string(hdr[4:7])
	switch ver {
	case "035", "036", "037", "038", "039", "040", "041":
	default:
		return nil, fmt.Errorf("views: unsupported DEX version %q", ver)
	}
	// The endian tag is written in the file's own byte order: read as LE it
	// is 0x12345678 for a little-endian file and 0x78563412 for a
	// reverse-endian (big-endian) one.
	var bo binary.ByteOrder
	switch binary.LittleEndian.Uint32(hdr[40:]) {
	case 0x12345678:
		bo = binary.LittleEndian
	case 0x78563412:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("views: invalid DEX header")
	}
	d := &Dex{Version: ver, FileSize: bo.Uint32(hdr[32:]), HeaderSize: bo.Uint32(hdr[36:])}
	if d.HeaderSize < 112 || d.FileSize < d.HeaderSize {
		return nil, fmt.Errorf("views: invalid DEX header")
	}
	if int64(d.FileSize) > size {
		return nil, fmt.Errorf("views: DEX file_size %d exceeds input size %d", d.FileSize, size)
	}
	d.StringCount = bo.Uint32(hdr[56:])
	d.TypeCount = bo.Uint32(hdr[64:])
	d.ProtoCount = bo.Uint32(hdr[72:])
	d.FieldCount = bo.Uint32(hdr[80:])
	d.MethodCount = bo.Uint32(hdr[88:])
	d.ClassCount = bo.Uint32(hdr[96:])
	// Each *_ids section must lie inside the declared file size.
	ids := []struct {
		count, off uint32
		elem       uint64
	}{
		{d.StringCount, bo.Uint32(hdr[60:]), 4},
		{d.TypeCount, bo.Uint32(hdr[68:]), 4},
		{d.ProtoCount, bo.Uint32(hdr[76:]), 12},
		{d.FieldCount, bo.Uint32(hdr[84:]), 8},
		{d.MethodCount, bo.Uint32(hdr[92:]), 8},
		{d.ClassCount, bo.Uint32(hdr[100:]), 32},
	}
	for _, s := range ids {
		if s.count > 0 && uint64(s.off)+uint64(s.count)*s.elem > uint64(d.FileSize) {
			return nil, fmt.Errorf("views: DEX ids section (off %d, count %d) exceeds file_size %d", s.off, s.count, d.FileSize)
		}
	}
	return d, nil
}
