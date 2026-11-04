package views

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// APKSigningBlock is the APK Signing Block that sits between the last ZIP
// entry and the central directory and carries v2/v3/v4 signatures.
type APKSigningBlock struct {
	Offset  int64
	Size    int64
	Schemes []string // "v2", "v3", "v3.1", "source-stamp", ...
	IDs     []uint32 // every pair ID, in order
}

var apkSigIDs = map[uint32]string{
	0x7109871a: "v2",
	0xf05368c0: "v3",
	0x1b93ad61: "v3.1",
	0x6dff800d: "source-stamp",
	0x2146444e: "play-frosting",
	0x42726577: "padding",
	0x504b4453: "dependency-info",
}

// Describe implements Describer.
func (b *APKSigningBlock) Describe() map[string]any {
	return map[string]any{"offset": b.Offset, "size": b.Size, "schemes": strs(b.Schemes)}
}

var apkSigMagic = []byte("APK Sig Block 42")

// ParseAPKSigningBlock locates the block via the EOCD's central directory
// offset. Inputs without one return an error.
func ParseAPKSigningBlock(ra io.ReaderAt, size int64) (*APKSigningBlock, error) {
	z := &Zip{}
	z.layout(ra, size)
	if z.EOCDOffset == 0 {
		return nil, fmt.Errorf("views: no ZIP end-of-central-directory record")
	}
	rec, err := readExact(ra, size, z.EOCDOffset, eocdLen)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	cdOffset := int64(le.Uint32(rec[16:])) + z.PrependedBytes
	if le.Uint32(rec[16:]) == 0xffffffff {
		// ZIP64: the locator (20 bytes) sits immediately before the EOCD
		// and points at the ZIP64 record, whose cd offset is at +48.
		loc, err := readExact(ra, size, z.EOCDOffset-20, 20)
		if err != nil || le.Uint32(loc) != 0x07064b50 {
			return nil, fmt.Errorf("views: no ZIP64 end-of-central-directory locator")
		}
		rec64, err := readExact(ra, size, clampInt64(le.Uint64(loc[8:]))+z.PrependedBytes, 56)
		if err != nil || le.Uint32(rec64) != 0x06064b50 {
			return nil, fmt.Errorf("views: no ZIP64 end-of-central-directory record")
		}
		cdOffset = clampInt64(le.Uint64(rec64[48:])) + z.PrependedBytes
	}
	if cdOffset < 32 {
		return nil, fmt.Errorf("views: no APK signing block")
	}
	footer, err := readExact(ra, size, cdOffset-24, 24)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(footer[8:], apkSigMagic) {
		return nil, fmt.Errorf("views: no APK signing block")
	}
	blockSize := int64(le.Uint64(footer)) // excludes the leading size field
	start := cdOffset - blockSize - 8
	if blockSize < 24 || start < 0 || blockSize > 64<<20 {
		return nil, fmt.Errorf("views: implausible APK signing block size %d", blockSize)
	}
	body, err := readExact(ra, size, start, blockSize+8)
	if err != nil {
		return nil, err
	}
	if int64(le.Uint64(body)) != blockSize {
		return nil, fmt.Errorf("views: APK signing block size fields disagree")
	}
	b := &APKSigningBlock{Offset: start, Size: blockSize + 8}
	pairs := body[8 : len(body)-24]
	seen := map[string]bool{}
	for len(pairs) >= 12 {
		n := int64(le.Uint64(pairs))
		if n < 4 || n > int64(len(pairs)-8) {
			return nil, fmt.Errorf("views: malformed APK signing block pair")
		}
		id := le.Uint32(pairs[8:])
		b.IDs = append(b.IDs, id)
		if name, ok := apkSigIDs[id]; ok && name != "padding" && !seen[name] {
			seen[name] = true
			b.Schemes = append(b.Schemes, name)
		}
		pairs = pairs[8+n:]
	}
	sort.Strings(b.Schemes)
	return b, nil
}
