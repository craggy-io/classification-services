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
	le := binary.LittleEndian
	d := &Dex{Version: ver, FileSize: le.Uint32(hdr[32:]), HeaderSize: le.Uint32(hdr[36:])}
	endian := le.Uint32(hdr[40:])
	if d.HeaderSize < 112 || (endian != 0x12345678 && endian != 0x78563412) {
		return nil, fmt.Errorf("views: invalid DEX header")
	}
	if int64(d.FileSize) > size {
		return nil, fmt.Errorf("views: DEX file_size %d exceeds input size %d", d.FileSize, size)
	}
	d.StringCount = le.Uint32(hdr[56:])
	d.TypeCount = le.Uint32(hdr[64:])
	d.ProtoCount = le.Uint32(hdr[72:])
	d.FieldCount = le.Uint32(hdr[80:])
	d.MethodCount = le.Uint32(hdr[88:])
	d.ClassCount = le.Uint32(hdr[96:])
	return d, nil
}
