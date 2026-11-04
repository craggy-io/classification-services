package views_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/craggy-io/classification-services/internal/testkit"
	"github.com/craggy-io/classification-services/views"
)

func parse[T any](t *testing.T, name string, b []byte) T {
	t.Helper()
	p, ok := views.Lookup(name)
	if !ok {
		t.Fatalf("view %q not registered", name)
	}
	v, err := p(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v.(T)
}

func TestZipLayoutAnomalies(t *testing.T) {
	plain := testkit.Zip(testkit.File{Name: "a.txt", Data: []byte("a")})
	z := parse[*views.Zip](t, "zip", plain)
	if z.PrependedBytes != 0 || z.TrailingBytes != 0 || len(z.Duplicates)+len(z.Traversal) != 0 {
		t.Fatalf("clean zip reported anomalies: %+v", z.Describe())
	}

	stub := append(testkit.ELF(256), plain...)
	z = parse[*views.Zip](t, "zip", stub)
	if z.PrependedBytes != 256 {
		t.Fatalf("PrependedBytes = %d, want 256", z.PrependedBytes)
	}

	evil := testkit.Zip(
		testkit.File{Name: "x", Data: []byte("1")},
		testkit.File{Name: "x", Data: []byte("2")},
		testkit.File{Name: "../../etc/passwd", Data: []byte("root")},
		testkit.File{Name: "/abs", Data: nil},
	)
	z = parse[*views.Zip](t, "zip", append(evil, "trailer"...))
	if !slices.Equal(z.Duplicates, []string{"x"}) {
		t.Fatalf("Duplicates = %v", z.Duplicates)
	}
	if !slices.Equal(z.Traversal, []string{"../../etc/passwd", "/abs"}) {
		t.Fatalf("Traversal = %v", z.Traversal)
	}
	if z.TrailingBytes != int64(len("trailer")) {
		t.Fatalf("TrailingBytes = %d", z.TrailingBytes)
	}
}

func TestELFImageEnd(t *testing.T) {
	img := testkit.ELF(512)
	e := parse[*views.ELF](t, "elf", append(img, "OVERLAY"...))
	if e.Class != 64 || e.MachineName != "x86-64" || e.ImageEnd != 512 || e.Segments != 1 {
		t.Fatalf("ELF = %+v", e)
	}
}

func TestPE(t *testing.T) {
	p := parse[*views.PE](t, "pe", testkit.PE(true, true))
	if !p.DLL || !p.DotNet || !p.PE32Plus || p.MachineName != "x86-64" || len(p.Sections) != 1 || p.Sections[0].Name != ".text" {
		t.Fatalf("PE = %+v", p)
	}
	if p.ImageEnd != 0x400 || p.OverlaySize != 0 {
		t.Fatalf("ImageEnd = %#x overlay = %d", p.ImageEnd, p.OverlaySize)
	}
	withOverlay := append(testkit.PE(false, false), "PK\x03\x04payload"...)
	p = parse[*views.PE](t, "pe", withOverlay)
	if p.OverlayOffset != 0x400 || p.OverlaySize != 11 {
		t.Fatalf("overlay = %#x+%d", p.OverlayOffset, p.OverlaySize)
	}
	if _, err := views.ParsePE(bytes.NewReader([]byte("MZ"+string(make([]byte, 100)))), 102); err != views.ErrDOSOnly {
		t.Fatalf("DOS stub err = %v", err)
	}
}

func TestMachOAgainstJavaClass(t *testing.T) {
	java := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := views.ParseMachO(bytes.NewReader(java), int64(len(java))); err == nil {
		t.Fatal("a Java class parsed as a universal Mach-O")
	}
	fat := make([]byte, 8192)
	copy(fat, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1, 0x01, 0, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0x08, 0})
	m := parse[*views.MachO](t, "macho", fat)
	if !m.Universal || len(m.Arches) != 1 || m.Arches[0].CPUName != "arm64" {
		t.Fatalf("MachO = %+v", m)
	}
}

func TestAXMLManifest(t *testing.T) {
	x := parse[*views.AXML](t, "axml", testkit.AXML("com.example.app", true, "android.permission.INTERNET", "android.permission.CAMERA"))
	m, err := x.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.Package != "com.example.app" || !m.Debuggable || !slices.Equal(m.Permissions, []string{"android.permission.INTERNET", "android.permission.CAMERA"}) {
		t.Fatalf("Manifest = %+v", m)
	}
}

func TestAPKSigningBlock(t *testing.T) {
	z := testkit.Zip(testkit.File{Name: "AndroidManifest.xml", Data: []byte("x")})
	b := parse[*views.APKSigningBlock](t, "apk-signing-block", testkit.WithSigningBlock(z, 0x7109871a, 0xf05368c0, 0x42726577))
	if !slices.Equal(b.Schemes, []string{"v2", "v3"}) {
		t.Fatalf("Schemes = %v", b.Schemes)
	}
	if _, err := views.ParseAPKSigningBlock(bytes.NewReader(z), int64(len(z))); err == nil {
		t.Fatal("unsigned zip reported a signing block")
	}
	// The ZIP must still parse once the block is inserted.
	parse[*views.Zip](t, "zip", testkit.WithSigningBlock(z, 0x7109871a))
}

func TestCFB(t *testing.T) {
	c := parse[*views.CFB](t, "cfb", testkit.CFB("WordDocument", "Macros", "1Table"))
	if c.Kind != "word" || !c.Macros || !slices.Contains(c.Entries, "WordDocument") {
		t.Fatalf("CFB = %+v", c)
	}
}

func TestPcapAndAr(t *testing.T) {
	p := parse[*views.Pcap](t, "pcap", testkit.Pcap(3))
	if p.Format != "pcap" || p.Packets != 3 || !p.PacketsExact || p.LinkName != "ethernet" {
		t.Fatalf("Pcap = %+v", p)
	}
	ar := []byte("!<arch>\ndebian-binary   0           0     0     100644  4         `\n2.0\n")
	a := parse[*views.Ar](t, "ar", ar)
	if !a.Debian || len(a.Members) != 1 || a.Members[0].Size != 4 {
		t.Fatalf("Ar = %+v", a)
	}
}

// Every parser must reject arbitrary prefixes of valid inputs without
// panicking.
func TestTruncatedInputsDoNotPanic(t *testing.T) {
	samples := [][]byte{
		testkit.Zip(testkit.File{Name: "a", Data: []byte("abc")}), testkit.ELF(200), testkit.PE(true, true),
		testkit.AXML("p", false, "q"), testkit.CFB("WordDocument"), testkit.Pcap(2),
	}
	for _, s := range samples {
		for n := 0; n <= len(s); n += max(1, len(s)/97) {
			for _, name := range views.Names() {
				p, _ := views.Lookup(name)
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("%s panicked on a %d-byte prefix: %v", name, n, r)
						}
					}()
					p(bytes.NewReader(s[:n]), int64(n))
				}()
			}
		}
	}
}

func FuzzViews(f *testing.F) {
	f.Add(testkit.Zip(testkit.File{Name: "a", Data: []byte("abc")}))
	f.Add(testkit.ELF(128))
	f.Add(testkit.PE(false, true))
	f.Add(testkit.AXML("p", true))
	f.Add(testkit.CFB("Workbook"))
	f.Add(testkit.Pcap(1))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, name := range views.Names() {
			p, _ := views.Lookup(name)
			p(bytes.NewReader(b), int64(len(b)))
		}
	})
}
