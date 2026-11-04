package views

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MachO is a parsed Mach-O header. A universal ("fat") binary lists its
// per-architecture slices in Arches; a thin binary has none.
type MachO struct {
	Universal bool
	Bits      int // 32 or 64 for thin binaries
	CPUType   uint32
	CPUName   string
	FileType  uint32 // MH_EXECUTE=2, MH_DYLIB=6, MH_BUNDLE=8, ...
	Commands  uint32
	Arches    []MachOArch
}

// MachOArch is one slice of a universal binary.
type MachOArch struct {
	CPUType uint32
	CPUName string
	Offset  int64
	Size    int64
}

var machoCPUs = map[uint32]string{
	7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000c: "arm64", 0x0200000c: "arm64_32",
	18: "ppc", 0x01000012: "ppc64",
}

// Describe implements Describer.
func (m *MachO) Describe() map[string]any {
	arches := make([]any, len(m.Arches))
	for i, a := range m.Arches {
		arches[i] = a.CPUName
	}
	return map[string]any{
		"universal": m.Universal, "bits": int64(m.Bits), "cpu": m.CPUName,
		"file_type": int64(m.FileType), "commands": int64(m.Commands), "arches": arches,
	}
}

const maxFatArches = 32

// ParseMachO parses a thin or universal Mach-O header. Universal binaries
// share the 0xcafebabe magic with Java class files; a plausible architecture
// count (Java's minor/major version makes the count at least 45) and slices
// lying inside the file tell them apart.
func ParseMachO(ra io.ReaderAt, size int64) (*MachO, error) {
	hdr, err := ReadRange(ra, size, 0, 32)
	if err != nil {
		return nil, err
	}
	if len(hdr) < 28 {
		return nil, fmt.Errorf("views: truncated Mach-O header")
	}
	be, le := binary.BigEndian, binary.LittleEndian
	switch be.Uint32(hdr) {
	case 0xcafebabe, 0xcafebabf:
		n := be.Uint32(hdr[4:])
		if n == 0 || n > maxFatArches {
			return nil, fmt.Errorf("views: not a universal Mach-O (%d arches)", n)
		}
		wide := be.Uint32(hdr) == 0xcafebabf
		entry := int64(20)
		if wide {
			entry = 32
		}
		tbl, err := readExact(ra, size, 8, int64(n)*entry)
		if err != nil {
			return nil, err
		}
		m := &MachO{Universal: true}
		for i := int64(0); i < int64(n); i++ {
			e := tbl[i*entry:]
			a := MachOArch{CPUType: be.Uint32(e)}
			if wide {
				a.Offset, a.Size = int64(be.Uint64(e[8:])), int64(be.Uint64(e[16:]))
			} else {
				a.Offset, a.Size = int64(be.Uint32(e[8:])), int64(be.Uint32(e[12:]))
			}
			if a.Offset <= 0 || a.Size <= 0 || a.Offset+a.Size > size {
				return nil, fmt.Errorf("views: universal Mach-O slice %d outside the file", i)
			}
			a.CPUName = machoCPUs[a.CPUType]
			m.Arches = append(m.Arches, a)
		}
		return m, nil
	}
	m := &MachO{}
	var bo binary.ByteOrder
	switch le.Uint32(hdr) {
	case 0xfeedface:
		bo, m.Bits = le, 32
	case 0xfeedfacf:
		bo, m.Bits = le, 64
	case 0xcefaedfe:
		bo, m.Bits = be, 32
	case 0xcffaedfe:
		bo, m.Bits = be, 64
	default:
		return nil, fmt.Errorf("views: not a Mach-O file")
	}
	m.CPUType = bo.Uint32(hdr[4:])
	m.CPUName = machoCPUs[m.CPUType]
	m.FileType = bo.Uint32(hdr[12:])
	m.Commands = bo.Uint32(hdr[16:])
	if m.FileType == 0 || m.FileType > 12 {
		return nil, fmt.Errorf("views: invalid Mach-O file type %d", m.FileType)
	}
	return m, nil
}
