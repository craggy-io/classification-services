package probes

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"

	"github.com/craggy-io/classification-services/evidence"
)

// decompress reads up to limit+1 bytes so callers can tell "exactly at the
// limit" from "over it".
func decompress(r io.Reader, limit int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, err
}

func bombNote(typ string, limit int64) evidence.Anomaly {
	return evidence.Anomaly{
		Code: "compression.expansion-limit", Severity: evidence.Warning,
		Message:  typ + " payload exceeds the expansion limit; not derived",
		Metadata: map[string]any{"limit_bytes": limit},
	}
}

// Gzip validates a gzip stream and derives its payload.
func Gzip(_ context.Context, in Input) ([]Finding, error) {
	gz, err := gzip.NewReader(io.NewSectionReader(in.Reader(), 0, in.Size()))
	if err != nil {
		head, _ := in.Prefix(3)
		if bytes.Equal(head, []byte{0x1f, 0x8b, 0x08}) {
			return []Finding{Reject("compression.gzip", Validated)}, nil
		}
		return nil, nil
	}
	defer gz.Close()
	gz.Multistream(true)
	md := map[string]any{"os": int(gz.OS)}
	if gz.Name != "" {
		md["name"] = gz.Name
	}
	if gz.Comment != "" {
		md["comment"] = gz.Comment
	}
	limit := expansionLimit(in, in.Size())
	data, over, err := decompress(gz, limit)
	if err != nil {
		return []Finding{Match("compression.gzip", Recognised, md)}, nil
	}
	f := Match("compression.gzip", Validated, md)
	if over {
		f.Anomalies = append(f.Anomalies, bombNote("gzip", limit))
		return []Finding{f}, nil
	}
	md["uncompressed_size"] = int64(len(data))
	name := gz.Name
	if name == "" {
		name = "gzip payload"
	}
	f.Children = []Derived{{Name: name, Data: data}}
	return []Finding{f}, nil
}

// Bzip2 validates a bzip2 stream and derives its payload.
func Bzip2(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(4)
	if err != nil || len(head) < 4 || !bytes.HasPrefix(head, []byte("BZh")) || head[3] < '1' || head[3] > '9' {
		return nil, err
	}
	limit := expansionLimit(in, in.Size())
	data, over, err := decompress(bzip2.NewReader(io.NewSectionReader(in.Reader(), 0, in.Size())), limit)
	if err != nil {
		return []Finding{Reject("compression.bzip2", Validated)}, nil
	}
	f := Match("compression.bzip2", Validated, map[string]any{"block_size": int(head[3] - '0')})
	if over {
		f.Anomalies = append(f.Anomalies, bombNote("bzip2", limit))
		return []Finding{f}, nil
	}
	f.Metadata["uncompressed_size"] = int64(len(data))
	f.Children = []Derived{{Name: "bzip2 payload", Data: data}}
	return []Finding{f}, nil
}

// Zlib validates a zlib stream (RFC 1950) and derives its payload.
func Zlib(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(2)
	if err != nil || len(head) < 2 {
		return nil, err
	}
	if head[0]&0x0f != 8 || head[0]>>4 > 7 || (uint16(head[0])<<8|uint16(head[1]))%31 != 0 {
		return nil, nil
	}
	zr, err := zlib.NewReader(io.NewSectionReader(in.Reader(), 0, in.Size()))
	if err != nil {
		return nil, nil
	}
	defer zr.Close()
	limit := expansionLimit(in, in.Size())
	data, over, err := decompress(zr, limit)
	if err != nil {
		return nil, nil // the two header bytes alone are too weak to reject on
	}
	f := Match("compression.zlib", Validated, map[string]any{"level": int(head[1] >> 6)})
	if over {
		f.Anomalies = append(f.Anomalies, bombNote("zlib", limit))
		return []Finding{f}, nil
	}
	f.Metadata["uncompressed_size"] = int64(len(data))
	f.Children = []Derived{{Name: "zlib payload", Data: data}}
	return []Finding{f}, nil
}

var xzMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

// XZ validates the xz stream header (magic, flags and their CRC32). The
// standard library has no xz decoder, so the payload is not derived.
func XZ(_ context.Context, in Input) ([]Finding, error) {
	h, err := in.Prefix(12)
	if err != nil || len(h) < 12 || !bytes.Equal(h[:6], xzMagic) {
		return nil, err
	}
	if h[6] != 0 || h[7] > 0x0f || crc32.ChecksumIEEE(h[6:8]) != binary.LittleEndian.Uint32(h[8:]) {
		return []Finding{Reject("compression.xz", Validated)}, nil
	}
	checks := map[byte]string{0: "none", 1: "crc32", 4: "crc64", 10: "sha256"}
	return []Finding{Match("compression.xz", Validated, map[string]any{"check": checks[h[7]]})}, nil
}

// Zstd validates a Zstandard frame header. The standard library has no
// zstd decoder, so the payload is not derived.
func Zstd(_ context.Context, in Input) ([]Finding, error) {
	h, err := in.Prefix(6)
	if err != nil || len(h) < 5 || !bytes.Equal(h[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		return nil, err
	}
	fhd := h[4]
	if fhd&0x08 != 0 { // reserved bit must be zero
		return []Finding{Reject("compression.zstd", Validated)}, nil
	}
	return []Finding{Match("compression.zstd", Recognised, map[string]any{
		"checksum": fhd&0x04 != 0, "single_segment": fhd&0x20 != 0,
	})}, nil
}
