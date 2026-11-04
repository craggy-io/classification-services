package views_test

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/craggy-io/classification-services/internal/testkit"
	"github.com/craggy-io/classification-services/views"
)

func TestMachOFat64OverflowRejected(t *testing.T) {
	b := make([]byte, 40)
	be := binary.BigEndian
	be.PutUint32(b[0:], 0xcafebabf)
	be.PutUint32(b[4:], 1)
	be.PutUint64(b[16:], math.MaxInt64) // slice offset
	be.PutUint64(b[24:], math.MaxInt64) // slice size
	if _, err := views.ParseMachO(bytes.NewReader(b), int64(len(b))); err == nil {
		t.Fatal("overflowing FAT64 slice accepted")
	}
}

func TestDexReverseEndian(t *testing.T) {
	b := make([]byte, 112)
	copy(b, "dex\n039\x00")
	be := binary.BigEndian
	be.PutUint32(b[32:], 112)        // file_size
	be.PutUint32(b[36:], 112)        // header_size
	be.PutUint32(b[40:], 0x12345678) // stored big-endian: read LE it is the reverse tag
	d, err := views.ParseDex(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if d.FileSize != 112 || d.HeaderSize != 112 {
		t.Fatalf("dex = %+v", d)
	}
}

func TestELFZeroEntrySizeRejected(t *testing.T) {
	b := testkit.ELF(512)
	b[54], b[55] = 0, 0 // e_phentsize = 0 with e_phnum = 1
	if _, err := views.ParseELF(bytes.NewReader(b), int64(len(b))); err == nil {
		t.Fatal("ELF with phnum>0 and phentsize=0 accepted")
	}
}

func TestPEDirectoriesBoundedByCount(t *testing.T) {
	b := testkit.PE(false, true)
	// NumberOfRvaAndSizes := 0 (optional header at 0x98, field at +108):
	// the CLR directory bytes that follow must not be read.
	for i := 0; i < 4; i++ {
		b[0x98+108+i] = 0
	}
	p, err := views.ParsePE(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if p.DotNet {
		t.Fatal("DotNet set although NumberOfRvaAndSizes is 0")
	}
}

func TestArLongNames(t *testing.T) {
	// BSD form: name stored at the start of the member data.
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	name := "a-very-long-member-name.o"
	data := append([]byte(name), []byte("DATA")...)
	hdr := make([]byte, 60)
	for i := range hdr {
		hdr[i] = ' '
	}
	copy(hdr, "#1/25")
	copy(hdr[48:], "29")
	hdr[58], hdr[59] = '`', '\n'
	b.Write(hdr)
	b.Write(data)
	b.WriteByte('\n') // pad to even
	a, err := views.ParseAr(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Members) != 1 || a.Members[0].Name != name || a.Members[0].Size != 4 {
		t.Fatalf("members = %+v", a.Members)
	}
}
