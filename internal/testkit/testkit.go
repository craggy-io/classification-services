// Package testkit builds small, valid sample files for tests: ZIPs, ELF and
// PE images, Android binary XML, compound files and captures. Everything is
// generated in code so the corpus needs no binary fixtures.
package testkit

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"strconv"
	"time"
	"unicode/utf16"
)

// File is one archive member.
type File struct {
	Name  string
	Data  []byte
	Store bool // stored, not deflated
}

// Zip builds a ZIP archive.
func Zip(files ...File) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, f := range files {
		h := &zip.FileHeader{Name: f.Name, Method: zip.Deflate, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		if f.Store {
			h.Method = zip.Store
		}
		fw, err := w.CreateHeader(h)
		if err != nil {
			panic(err)
		}
		fw.Write(f.Data)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// Gzip compresses data.
func Gzip(data []byte, name string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Name = name
	w.ModTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

// Zlib compresses data.
func Zlib(data []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

// Tar builds a tar archive of regular files.
func Tar(files ...File) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, f := range files {
		w.WriteHeader(&tar.Header{Name: f.Name, Mode: 0o644, Size: int64(len(f.Data)), Typeflag: tar.TypeReg, ModTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
		w.Write(f.Data)
	}
	w.Close()
	return b.Bytes()
}

// ELF builds a minimal little-endian ELF64 executable with one PT_LOAD
// segment covering the first size bytes.
func ELF(size int) []byte {
	size = max(size, 64+56)
	b := make([]byte, size)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2)  // ET_EXEC
	le.PutUint16(b[18:], 62) // x86-64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[24:], 0x401000)
	le.PutUint64(b[32:], 64) // phoff
	le.PutUint16(b[52:], 64) // ehsize
	le.PutUint16(b[54:], 56) // phentsize
	le.PutUint16(b[56:], 1)  // phnum
	ph := b[64:]
	le.PutUint32(ph[0:], 1)             // PT_LOAD
	le.PutUint64(ph[8:], 0)             // offset
	le.PutUint64(ph[32:], uint64(size)) // filesz
	le.PutUint64(ph[40:], uint64(size)) // memsz
	return b
}

// PE builds a minimal PE32+ image with one section. dll sets the DLL flag
// and dotnet adds a CLR runtime header directory.
func PE(dll, dotnet bool) []byte {
	b := make([]byte, 0x400)
	le := binary.LittleEndian
	b[0], b[1] = 'M', 'Z'
	le.PutUint32(b[60:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	coff := b[0x84:]
	le.PutUint16(coff[0:], 0x8664)
	le.PutUint16(coff[2:], 1)    // sections
	le.PutUint16(coff[16:], 240) // optional header size
	ch := uint16(0x0022)
	if dll {
		ch |= 0x2000
	}
	le.PutUint16(coff[18:], ch)
	opt := b[0x98:]
	le.PutUint16(opt[0:], 0x20b)
	le.PutUint32(opt[16:], 0x1000)
	le.PutUint32(opt[60:], 0x200) // SizeOfHeaders
	le.PutUint16(opt[68:], 3)     // console
	le.PutUint32(opt[108:], 16)   // NumberOfRvaAndSizes
	if dotnet {
		le.PutUint32(opt[112+14*8:], 0x2000)
		le.PutUint32(opt[112+14*8+4:], 72)
	}
	sec := b[0x98+240:]
	copy(sec, ".text")
	le.PutUint32(sec[8:], 0x200)
	le.PutUint32(sec[16:], 0x200) // raw size
	le.PutUint32(sec[20:], 0x200) // raw offset
	return b
}

// AXML builds Android binary XML for a manifest with a package name,
// permissions and an optional debuggable application.
func AXML(pkg string, debuggable bool, permissions ...string) []byte {
	strs := []string{"manifest", "package", pkg, "uses-permission", "name", "application", "debuggable"}
	strs = append(strs, permissions...)
	idx := func(s string) uint32 {
		for i, x := range strs {
			if x == s {
				return uint32(i)
			}
		}
		panic(s)
	}
	le := binary.LittleEndian
	// string pool (UTF-16)
	var data bytes.Buffer
	offsets := make([]uint32, len(strs))
	for i, s := range strs {
		offsets[i] = uint32(data.Len())
		u := utf16.Encode([]rune(s))
		binary.Write(&data, le, uint16(len(u)))
		binary.Write(&data, le, u)
		binary.Write(&data, le, uint16(0))
	}
	for data.Len()%4 != 0 {
		data.WriteByte(0)
	}
	var pool bytes.Buffer
	hdr := 28
	start := hdr + 4*len(strs)
	binary.Write(&pool, le, uint16(0x0001))
	binary.Write(&pool, le, uint16(hdr))
	binary.Write(&pool, le, uint32(start+data.Len()))
	binary.Write(&pool, le, uint32(len(strs)))
	binary.Write(&pool, le, uint32(0))
	binary.Write(&pool, le, uint32(0)) // UTF-16
	binary.Write(&pool, le, uint32(start))
	binary.Write(&pool, le, uint32(0))
	binary.Write(&pool, le, offsets)
	pool.Write(data.Bytes())

	type attr struct {
		name  string
		dtype byte
		data  uint32
		raw   uint32
	}
	elem := func(name string, attrs ...attr) []byte {
		var e bytes.Buffer
		size := 16 + 20 + 20*len(attrs)
		binary.Write(&e, le, uint16(0x0102))
		binary.Write(&e, le, uint16(16))
		binary.Write(&e, le, uint32(size))
		binary.Write(&e, le, uint32(1))          // line
		binary.Write(&e, le, uint32(0xffffffff)) // comment
		binary.Write(&e, le, uint32(0xffffffff)) // ns
		binary.Write(&e, le, idx(name))
		binary.Write(&e, le, uint16(20)) // attributeStart
		binary.Write(&e, le, uint16(20)) // attributeSize
		binary.Write(&e, le, uint16(len(attrs)))
		binary.Write(&e, le, [3]uint16{})
		for _, a := range attrs {
			binary.Write(&e, le, uint32(0xffffffff))
			binary.Write(&e, le, idx(a.name))
			binary.Write(&e, le, a.raw)
			binary.Write(&e, le, uint16(8))
			e.WriteByte(0)
			e.WriteByte(a.dtype)
			binary.Write(&e, le, a.data)
		}
		return e.Bytes()
	}
	end := func(name string) []byte {
		var e bytes.Buffer
		binary.Write(&e, le, uint16(0x0103))
		binary.Write(&e, le, uint16(16))
		binary.Write(&e, le, uint32(24))
		binary.Write(&e, le, uint32(1))
		binary.Write(&e, le, uint32(0xffffffff))
		binary.Write(&e, le, uint32(0xffffffff))
		binary.Write(&e, le, idx(name))
		return e.Bytes()
	}
	var body bytes.Buffer
	body.Write(pool.Bytes())
	body.Write(elem("manifest", attr{"package", 0x03, idx(pkg), idx(pkg)}))
	for _, p := range permissions {
		body.Write(elem("uses-permission", attr{"name", 0x03, idx(p), idx(p)}))
		body.Write(end("uses-permission"))
	}
	dbg := uint32(0)
	if debuggable {
		dbg = 0xffffffff
	}
	body.Write(elem("application", attr{"debuggable", 0x12, dbg, 0xffffffff}))
	body.Write(end("application"))
	body.Write(end("manifest"))
	var out bytes.Buffer
	binary.Write(&out, le, uint16(0x0003))
	binary.Write(&out, le, uint16(8))
	binary.Write(&out, le, uint32(8+body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

// WithSigningBlock inserts an APK Signing Block carrying the given pair IDs
// in front of a ZIP's central directory and fixes up the EOCD offset.
func WithSigningBlock(zipData []byte, ids ...uint32) []byte {
	le := binary.LittleEndian
	eocd := bytes.LastIndex(zipData, []byte("PK\x05\x06"))
	cd := int(le.Uint32(zipData[eocd+16:]))
	var pairs bytes.Buffer
	for _, id := range ids {
		binary.Write(&pairs, le, uint64(4+4))
		binary.Write(&pairs, le, id)
		binary.Write(&pairs, le, uint32(0))
	}
	size := uint64(pairs.Len() + 8 + 16)
	var block bytes.Buffer
	binary.Write(&block, le, size)
	block.Write(pairs.Bytes())
	binary.Write(&block, le, size)
	block.WriteString("APK Sig Block 42")
	out := append(append(append([]byte(nil), zipData[:cd]...), block.Bytes()...), zipData[cd:]...)
	le.PutUint32(out[eocd+block.Len()+16:], uint32(cd+block.Len()))
	return out
}

// CFB builds a compound file (512-byte sectors) whose directory holds the
// given storage/stream names after the root entry.
func CFB(names ...string) []byte {
	le := binary.LittleEndian
	const sector = 512
	ndir := (len(names) + 1 + 3) / 4
	b := make([]byte, sector*(2+ndir))
	h := b[:sector]
	copy(h, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	le.PutUint16(h[24:], 0x3e)
	le.PutUint16(h[26:], 3)
	le.PutUint16(h[28:], 0xfffe)
	le.PutUint16(h[30:], 9)
	le.PutUint16(h[32:], 6)
	le.PutUint32(h[44:], 1) // FAT sectors
	le.PutUint32(h[48:], 1) // first directory sector
	le.PutUint32(h[56:], 4096)
	le.PutUint32(h[60:], 0xfffffffe)
	le.PutUint32(h[68:], 0xfffffffe)
	for i := 0; i < 109; i++ {
		le.PutUint32(h[76+4*i:], 0xffffffff)
	}
	le.PutUint32(h[76:], 0) // DIFAT[0] = sector 0
	fat := b[sector : 2*sector]
	for i := 0; i < sector/4; i++ {
		le.PutUint32(fat[4*i:], 0xffffffff)
	}
	le.PutUint32(fat[0:], 0xfffffffd) // FAT sector
	for i := 0; i < ndir; i++ {
		next := uint32(2 + i)
		if i == ndir-1 {
			next = 0xfffffffe
		}
		le.PutUint32(fat[4*(1+i):], next)
	}
	entry := func(i int, name string, typ byte) {
		e := b[2*sector+128*i:]
		u := utf16.Encode([]rune(name))
		if len(u) > 31 {
			panic("testkit: CFB entry name exceeds 31 UTF-16 units: " + name)
		}
		for j, c := range u {
			le.PutUint16(e[2*j:], c)
		}
		le.PutUint16(e[64:], uint16(2*(len(u)+1)))
		e[66] = typ
		le.PutUint32(e[68:], 0xffffffff)
		le.PutUint32(e[72:], 0xffffffff)
		le.PutUint32(e[76:], 0xffffffff)
	}
	entry(0, "Root Entry", 5)
	for i, n := range names {
		entry(i+1, n, 2)
	}
	return b
}

// Pcap builds a classic little-endian pcap with n empty Ethernet records.
func Pcap(n int) []byte {
	le := binary.LittleEndian
	var b bytes.Buffer
	binary.Write(&b, le, []uint32{0xa1b2c3d4})
	binary.Write(&b, le, []uint16{2, 4})
	binary.Write(&b, le, []uint32{0, 0, 65535, 1})
	for i := 0; i < n; i++ {
		binary.Write(&b, le, []uint32{uint32(i), 0, 14, 14})
		b.Write(make([]byte, 14))
	}
	return b.Bytes()
}

// MachO builds a minimal thin Mach-O 64-bit executable header (arm64).
func MachO() []byte {
	b := make([]byte, 32)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0xfeedfacf)
	le.PutUint32(b[4:], 0x0100000c) // arm64
	le.PutUint32(b[12:], 2)         // MH_EXECUTE
	return b
}

// Ar builds a Unix ar archive with the given members.
func Ar(files ...File) []byte {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, f := range files {
		name := f.Name
		if len(name) > 15 {
			panic("testkit: ar member name too long: " + name)
		}
		hdr := make([]byte, 60)
		for i := range hdr {
			hdr[i] = ' '
		}
		copy(hdr, name+"/")
		copy(hdr[48:], []byte(strconv.Itoa(len(f.Data))))
		hdr[58], hdr[59] = '`', '\n'
		b.Write(hdr)
		b.Write(f.Data)
		if len(f.Data)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// PNG builds a minimal 1x1 PNG (signature and IHDR).
func PNG() []byte {
	var b bytes.Buffer
	b.Write([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 1)
	binary.BigEndian.PutUint32(ihdr[4:], 1)
	ihdr[8] = 8 // bit depth
	chunk := append([]byte("IHDR"), ihdr...)
	var lenBuf, crcBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 13)
	binary.BigEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(chunk))
	b.Write(lenBuf[:])
	b.Write(chunk)
	b.Write(crcBuf[:])
	return b.Bytes()
}

// SQLite builds a minimal SQLite 3 database header (512-byte page).
func SQLite() []byte {
	b := make([]byte, 512)
	copy(b, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(b[16:], 512)
	binary.BigEndian.PutUint32(b[56:], 1) // UTF-8
	return b
}

// XZHeader is a valid xz stream header (CRC64 check) followed by padding.
func XZHeader() []byte {
	h := []byte{0xfd, '7', 'z', 'X', 'Z', 0, 0, 4}
	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], crc32.ChecksumIEEE(h[6:8]))
	return append(append(h, crc[:]...), make([]byte, 20)...)
}
