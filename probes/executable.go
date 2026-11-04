package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"github.com/craggy-io/classification-services/evidence"
	"github.com/craggy-io/classification-services/views"
)

// overlay reports data appended after an executable image and derives it,
// so an archive or script hidden in the overlay is classified in turn.
func overlay(f *Finding, in Input, offset int64, format string) {
	n := in.Size() - offset
	if offset <= 0 || n <= 0 {
		return
	}
	head, _ := in.Read(offset, 4)
	sev := evidence.Info
	if bytes.HasPrefix(head, []byte("PK")) || bytes.HasPrefix(head, []byte("MZ")) || bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}) {
		sev = evidence.Warning
	}
	f.Anomalies = append(f.Anomalies, evidence.Anomaly{
		Code: "executable.overlay", Severity: sev,
		Message:  "data is appended after the " + format + " image",
		Metadata: map[string]any{"offset": offset, "bytes": n},
	})
	f.Children = append(f.Children, Derived{Name: "overlay", Offset: offset, Length: n})
}

// ELF validates an ELF image, identifies shared objects and reports an
// overlay.
func ELF(_ context.Context, in Input) ([]Finding, error) {
	e, err := view[*views.ELF](in, "elf")
	if err != nil {
		head, _ := in.Prefix(4)
		if bytes.Equal(head, []byte{0x7f, 'E', 'L', 'F'}) {
			return []Finding{Reject("executable.elf", Validated)}, nil
		}
		return nil, nil
	}
	md := e.Describe()
	f := Match("executable.elf", Validated, md)
	if e.Sections > 0 || e.Segments > 0 {
		overlay(&f, in, e.ImageEnd, "ELF")
	}
	out := []Finding{f}
	if e.Type == 3 && e.Interpreter == "" { // ET_DYN without PT_INTERP: a library, not a PIE executable
		out = append(out, Match("executable.elf-shared-object", Validated, nil))
	}
	return out, nil
}

// PE validates a PE/COFF image and identifies DLLs and .NET assemblies.
// An MZ file without a PE header is a DOS executable.
func PE(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(2)
	if err != nil || !bytes.Equal(head, []byte("MZ")) {
		return nil, err
	}
	p, err := view[*views.PE](in, "pe")
	if err != nil {
		if errors.Is(err, views.ErrDOSOnly) {
			return []Finding{Reject("executable.pe", Validated), Match("executable.dos-mz", Recognised, nil)}, nil
		}
		return []Finding{Reject("executable.pe", Validated)}, nil
	}
	f := Match("executable.pe", Validated, p.Describe())
	overlay(&f, in, p.OverlayOffset, "PE")
	out := []Finding{f}
	if p.DLL {
		out = append(out, Match("executable.pe-dll", Validated, nil))
	}
	if p.DotNet {
		out = append(out, Match("executable.dotnet", Validated, nil))
	}
	return out, nil
}

// MachO validates thin and universal Mach-O binaries.
func MachO(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(4)
	if err != nil || len(head) < 4 {
		return nil, err
	}
	m, err := view[*views.MachO](in, "macho")
	if err != nil {
		switch binary.LittleEndian.Uint32(head) {
		case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
			return []Finding{Reject("executable.macho", Validated)}, nil
		}
		return nil, nil // 0xcafebabe that is not universal is likely a Java class
	}
	if m.Universal {
		return []Finding{Match("executable.macho-universal", Validated, m.Describe())}, nil
	}
	return []Finding{Match("executable.macho", Validated, m.Describe())}, nil
}

// JavaClass validates a Java class file header.
func JavaClass(_ context.Context, in Input) ([]Finding, error) {
	b, err := in.Prefix(10)
	if err != nil {
		return nil, err
	}
	if len(b) < 10 || !bytes.Equal(b[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return nil, nil
	}
	be := binary.BigEndian
	minor, major, cp := be.Uint16(b[4:]), be.Uint16(b[6:]), be.Uint16(b[8:])
	if cp == 0 || major < 45 || major > 80 {
		return []Finding{Reject("executable.java-class", Validated)}, nil
	}
	return []Finding{Match("executable.java-class", Validated, map[string]any{
		"major_version": int(major), "minor_version": int(minor),
		"constant_pool_count": int(cp), "java_version": int(major) - 44,
	})}, nil
}
