package views

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// ELF is a parsed ELF header plus the extent of its program and section
// tables, which bounds the image so appended data (an overlay) is visible.
type ELF struct {
	Class        int // 32 or 64
	LittleEndian bool
	OSABI        int
	Type         int // ET_REL=1, ET_EXEC=2, ET_DYN=3, ET_CORE=4
	Machine      int
	MachineName  string
	Version      int
	Entry        uint64
	Segments     int
	Sections     int
	Interpreter  string // PT_INTERP, if present
	// ImageEnd is the furthest byte referenced by the headers, segments or
	// sections. Bytes beyond it are an overlay.
	ImageEnd int64
}

var elfMachines = map[int]string{
	0: "none", 3: "x86", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm",
	50: "ia64", 62: "x86-64", 183: "aarch64", 243: "riscv", 247: "bpf", 258: "loongarch",
}

// Describe implements Describer.
func (e *ELF) Describe() map[string]any {
	return map[string]any{
		"class": int64(e.Class), "little_endian": e.LittleEndian, "osabi": int64(e.OSABI),
		"type": int64(e.Type), "machine": int64(e.Machine), "machine_name": e.MachineName,
		"version": int64(e.Version), "entry": int64(e.Entry), "segments": int64(e.Segments),
		"sections": int64(e.Sections), "interpreter": e.Interpreter, "image_end": e.ImageEnd,
	}
}

const maxELFEntries = 4096

// ParseELF parses and validates an ELF header and walks its tables.
func ParseELF(ra io.ReaderAt, size int64) (*ELF, error) {
	hdr, err := ReadRange(ra, size, 0, 64)
	if err != nil {
		return nil, err
	}
	if len(hdr) < 52 || !bytes.Equal(hdr[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil, fmt.Errorf("views: not an ELF file")
	}
	e := &ELF{OSABI: int(hdr[7])}
	switch hdr[4] {
	case 1:
		e.Class = 32
	case 2:
		e.Class = 64
		if len(hdr) < 64 {
			return nil, fmt.Errorf("views: truncated ELF64 header")
		}
	default:
		return nil, fmt.Errorf("views: invalid ELF class %d", hdr[4])
	}
	var bo binary.ByteOrder
	switch hdr[5] {
	case 1:
		bo, e.LittleEndian = binary.LittleEndian, true
	case 2:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("views: invalid ELF data encoding %d", hdr[5])
	}
	if hdr[6] != 1 {
		return nil, fmt.Errorf("views: invalid ELF version %d", hdr[6])
	}
	e.Type = int(bo.Uint16(hdr[16:]))
	e.Machine = int(bo.Uint16(hdr[18:]))
	e.MachineName = elfMachines[e.Machine]
	e.Version = int(bo.Uint32(hdr[20:]))

	var phoff, shoff int64
	var ehsize, phentsize, phnum, shentsize, shnum int64
	if e.Class == 64 {
		e.Entry = bo.Uint64(hdr[24:])
		phoff = int64(bo.Uint64(hdr[32:]))
		shoff = int64(bo.Uint64(hdr[40:]))
		ehsize = int64(bo.Uint16(hdr[52:]))
		phentsize, phnum = int64(bo.Uint16(hdr[54:])), int64(bo.Uint16(hdr[56:]))
		shentsize, shnum = int64(bo.Uint16(hdr[58:])), int64(bo.Uint16(hdr[60:]))
	} else {
		e.Entry = uint64(bo.Uint32(hdr[24:]))
		phoff = int64(bo.Uint32(hdr[28:]))
		shoff = int64(bo.Uint32(hdr[32:]))
		ehsize = int64(bo.Uint16(hdr[40:]))
		phentsize, phnum = int64(bo.Uint16(hdr[42:])), int64(bo.Uint16(hdr[44:]))
		shentsize, shnum = int64(bo.Uint16(hdr[46:])), int64(bo.Uint16(hdr[48:]))
	}
	if phoff < 0 || shoff < 0 || phnum > maxELFEntries || shnum > maxELFEntries {
		return nil, fmt.Errorf("views: implausible ELF table geometry")
	}
	e.ImageEnd = max(ehsize, 52)
	extend := func(off, n int64) {
		if off >= 0 && n >= 0 && off <= size {
			e.ImageEnd = max(e.ImageEnd, off+n)
		}
	}
	if phnum > 0 && phentsize >= 32 {
		extend(phoff, phnum*phentsize)
		for i := int64(0); i < phnum; i++ {
			ph, err := readExact(ra, size, phoff+i*phentsize, min(phentsize, 56))
			if err != nil {
				return nil, fmt.Errorf("views: ELF program header %d: %w", i, err)
			}
			var ptype uint32
			var off, filesz int64
			if e.Class == 64 {
				if len(ph) < 56 {
					return nil, fmt.Errorf("views: short ELF64 program header")
				}
				ptype = bo.Uint32(ph[0:])
				off, filesz = int64(bo.Uint64(ph[8:])), int64(bo.Uint64(ph[32:]))
			} else {
				ptype = bo.Uint32(ph[0:])
				off, filesz = int64(bo.Uint32(ph[4:])), int64(bo.Uint32(ph[16:]))
			}
			e.Segments++
			extend(off, filesz)
			if ptype == 3 && filesz > 0 && filesz < 4096 { // PT_INTERP
				if b, err := ReadRange(ra, size, off, filesz); err == nil {
					e.Interpreter = string(bytes.TrimRight(b, "\x00"))
				}
			}
		}
	}
	if shnum > 0 && shentsize >= 40 {
		extend(shoff, shnum*shentsize)
		for i := int64(0); i < shnum; i++ {
			sh, err := readExact(ra, size, shoff+i*shentsize, min(shentsize, 64))
			if err != nil {
				return nil, fmt.Errorf("views: ELF section header %d: %w", i, err)
			}
			var stype uint32
			var off, sz int64
			if e.Class == 64 {
				if len(sh) < 40 {
					return nil, fmt.Errorf("views: short ELF64 section header")
				}
				stype = bo.Uint32(sh[4:])
				off, sz = int64(bo.Uint64(sh[24:])), int64(bo.Uint64(sh[32:]))
			} else {
				stype = bo.Uint32(sh[4:])
				off, sz = int64(bo.Uint32(sh[16:])), int64(bo.Uint32(sh[20:]))
			}
			e.Sections++
			if stype != 8 { // SHT_NOBITS occupies no file space
				extend(off, sz)
			}
		}
	}
	if e.ImageEnd > size {
		e.ImageEnd = size
	}
	return e, nil
}
