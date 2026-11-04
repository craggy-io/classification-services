package views

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrDOSOnly reports an MZ executable with no PE header (a DOS program).
var ErrDOSOnly = errors.New("views: MZ file without a PE header")

// PE is a parsed Windows Portable Executable (PE/COFF) image.
type PE struct {
	Machine         uint16
	MachineName     string
	Sections        []PESection
	Characteristics uint16
	DLL             bool
	PE32Plus        bool // 64-bit optional header
	Subsystem       uint16
	SubsystemName   string
	EntryPoint      uint32
	// DotNet is set when the CLR runtime header directory is present.
	DotNet bool
	// Signed is set when an Authenticode certificate table is present.
	Signed          bool
	CertOffset      int64
	CertSize        int64
	HeadersSize     int64
	ImageEnd        int64 // furthest raw byte covered by headers and sections
	OverlayOffset   int64 // ImageEnd, or the end of a trailing certificate
	OverlaySize     int64 // bytes after OverlayOffset
	TimeDateStamp   uint32
	NumberOfSymbols uint32
}

// PESection is one section header.
type PESection struct {
	Name            string
	VirtualSize     uint32
	RawOffset       uint32
	RawSize         uint32
	Characteristics uint32
}

var peMachines = map[uint16]string{
	0x014c: "x86", 0x8664: "x86-64", 0x01c0: "arm", 0x01c4: "armnt", 0xaa64: "arm64",
	0x0200: "ia64", 0x5064: "riscv64", 0x0ebc: "efi-bytecode",
}

var peSubsystems = map[uint16]string{
	1: "native", 2: "windows-gui", 3: "windows-cui", 7: "posix-cui", 9: "windows-ce",
	10: "efi-application", 11: "efi-boot-driver", 12: "efi-runtime-driver", 14: "xbox", 16: "boot-application",
}

// Describe implements Describer.
func (p *PE) Describe() map[string]any {
	names := make([]any, len(p.Sections))
	for i, s := range p.Sections {
		names[i] = s.Name
	}
	return map[string]any{
		"machine": int64(p.Machine), "machine_name": p.MachineName, "dll": p.DLL,
		"pe32_plus": p.PE32Plus, "subsystem": p.SubsystemName, "dotnet": p.DotNet,
		"signed": p.Signed, "sections": names, "image_end": p.ImageEnd,
		"overlay_offset": p.OverlayOffset, "overlay_size": p.OverlaySize,
		"entry_point": int64(p.EntryPoint), "timestamp": int64(p.TimeDateStamp),
	}
}

const maxPESections = 96

// ParsePE parses the DOS stub pointer, COFF header, optional header data
// directories and section table.
func ParsePE(ra io.ReaderAt, size int64) (*PE, error) {
	dos, err := ReadRange(ra, size, 0, 64)
	if err != nil {
		return nil, err
	}
	if len(dos) < 64 || dos[0] != 'M' || dos[1] != 'Z' {
		return nil, fmt.Errorf("views: not a PE file (no MZ header)")
	}
	le := binary.LittleEndian
	lfanew := int64(le.Uint32(dos[60:]))
	if lfanew < 64 || lfanew > 1<<20 || lfanew+24 > size {
		return nil, ErrDOSOnly
	}
	coff, err := readExact(ra, size, lfanew, 24)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(coff[:4], []byte("PE\x00\x00")) {
		return nil, ErrDOSOnly
	}
	p := &PE{
		Machine:         le.Uint16(coff[4:]),
		TimeDateStamp:   le.Uint32(coff[8:]),
		NumberOfSymbols: le.Uint32(coff[16:]),
		Characteristics: le.Uint16(coff[22:]),
	}
	p.MachineName = peMachines[p.Machine]
	p.DLL = p.Characteristics&0x2000 != 0
	nsec := int64(le.Uint16(coff[6:]))
	optSize := int64(le.Uint16(coff[20:]))
	if nsec > maxPESections {
		return nil, fmt.Errorf("views: %d PE sections exceeds limit %d", nsec, maxPESections)
	}
	optOff := lfanew + 24
	if optSize > 0 {
		opt, err := readExact(ra, size, optOff, min(optSize, 240))
		if err != nil {
			return nil, err
		}
		if len(opt) < 2 {
			return nil, fmt.Errorf("views: truncated PE optional header")
		}
		magic := le.Uint16(opt)
		var ddOff int
		switch magic {
		case 0x10b:
			ddOff = 96
		case 0x20b:
			p.PE32Plus = true
			ddOff = 112
		default:
			return nil, fmt.Errorf("views: unknown PE optional header magic %#x", magic)
		}
		if len(opt) >= 20 {
			p.EntryPoint = le.Uint32(opt[16:])
		}
		if len(opt) >= 64 {
			p.HeadersSize = int64(le.Uint32(opt[60:]))
		}
		if len(opt) >= 70 {
			p.Subsystem = le.Uint16(opt[68:])
			p.SubsystemName = peSubsystems[p.Subsystem]
		}
		numDirs := 16
		if len(opt) >= ddOff {
			numDirs = int(le.Uint32(opt[ddOff-4:])) // NumberOfRvaAndSizes
		}
		dir := func(i int) (uint32, uint32, bool) {
			o := ddOff + 8*i
			if i >= numDirs || len(opt) < o+8 {
				return 0, 0, false
			}
			return le.Uint32(opt[o:]), le.Uint32(opt[o+4:]), true
		}
		if off, sz, ok := dir(4); ok && sz > 0 { // certificate table: file offset, not RVA
			p.Signed, p.CertOffset, p.CertSize = true, int64(off), int64(sz)
		}
		if rva, sz, ok := dir(14); ok && rva != 0 && sz != 0 {
			p.DotNet = true
		}
	}
	secOff := optOff + optSize
	p.ImageEnd = max(p.HeadersSize, secOff+nsec*40)
	for i := int64(0); i < nsec; i++ {
		b, err := readExact(ra, size, secOff+i*40, 40)
		if err != nil {
			return nil, fmt.Errorf("views: PE section %d: %w", i, err)
		}
		s := PESection{
			Name:            string(bytes.TrimRight(b[:8], "\x00")),
			VirtualSize:     le.Uint32(b[8:]),
			RawSize:         le.Uint32(b[16:]),
			RawOffset:       le.Uint32(b[20:]),
			Characteristics: le.Uint32(b[36:]),
		}
		p.Sections = append(p.Sections, s)
		if s.RawSize > 0 {
			p.ImageEnd = max(p.ImageEnd, int64(s.RawOffset)+int64(s.RawSize))
		}
	}
	p.ImageEnd = min(p.ImageEnd, size)
	p.OverlayOffset = p.ImageEnd
	// A certificate table conventionally sits at the end of the file; it is
	// part of the signed image, not an overlay.
	if p.Signed && p.CertOffset >= p.ImageEnd && p.CertOffset+p.CertSize <= size {
		gap := p.CertOffset - p.ImageEnd
		if gap < 8 { // alignment padding
			p.OverlayOffset = p.CertOffset + p.CertSize
		}
	}
	p.OverlaySize = max(size-p.OverlayOffset, 0)
	return p, nil
}
