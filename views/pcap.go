package views

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Pcap is a parsed packet-capture header (classic libpcap or pcapng).
type Pcap struct {
	Format       string // "pcap" or "pcapng"
	LittleEndian bool
	Nanosecond   bool // classic pcap with nanosecond timestamps
	VersionMajor uint16
	VersionMinor uint16
	SnapLen      uint32
	LinkType     uint32
	LinkName     string
	// Packets counts records walked, up to a bound; PacketsExact reports
	// whether the walk reached the end of the file.
	Packets      int64
	PacketsExact bool
}

var linkTypes = map[uint32]string{
	0: "null", 1: "ethernet", 101: "raw", 105: "ieee802.11", 113: "linux-sll",
	127: "ieee802.11-radiotap", 228: "ipv4", 229: "ipv6", 276: "linux-sll2",
}

const maxPcapWalk = 100_000

// Describe implements Describer.
func (p *Pcap) Describe() map[string]any {
	return map[string]any{
		"format": p.Format, "little_endian": p.LittleEndian, "nanosecond": p.Nanosecond,
		"version": fmt.Sprintf("%d.%d", p.VersionMajor, p.VersionMinor), "snaplen": int64(p.SnapLen),
		"link_type": int64(p.LinkType), "link_name": p.LinkName,
		"packets": p.Packets, "packets_exact": p.PacketsExact,
	}
}

// ParsePcap parses a classic pcap or pcapng file and counts records.
func ParsePcap(ra io.ReaderAt, size int64) (*Pcap, error) {
	h, err := ReadRange(ra, size, 0, 24)
	if err != nil {
		return nil, err
	}
	if len(h) < 24 {
		return nil, fmt.Errorf("views: truncated capture header")
	}
	le, be := binary.LittleEndian, binary.BigEndian
	p := &Pcap{}
	var bo binary.ByteOrder
	switch le.Uint32(h) {
	case 0xa1b2c3d4:
		bo, p.LittleEndian = le, true
	case 0xa1b23c4d:
		bo, p.LittleEndian, p.Nanosecond = le, true, true
	case 0xd4c3b2a1:
		bo = be
	case 0x4d3cb2a1:
		bo, p.Nanosecond = be, true
	case 0x0a0d0d0a:
		return parsePcapNG(ra, size, h)
	default:
		return nil, fmt.Errorf("views: not a packet capture")
	}
	p.Format = "pcap"
	p.VersionMajor, p.VersionMinor = bo.Uint16(h[4:]), bo.Uint16(h[6:])
	if p.VersionMajor != 2 {
		return nil, fmt.Errorf("views: unsupported pcap version %d.%d", p.VersionMajor, p.VersionMinor)
	}
	p.SnapLen = bo.Uint32(h[16:])
	p.LinkType = bo.Uint32(h[20:]) & 0x0fffffff
	p.LinkName = linkTypes[p.LinkType]
	off := int64(24)
	for p.Packets < maxPcapWalk {
		rec, err := ReadRange(ra, size, off, 16)
		if err != nil || len(rec) < 16 {
			p.PacketsExact = err == nil && len(rec) == 0
			break
		}
		incl := int64(bo.Uint32(rec[8:]))
		if incl > 1<<26 {
			break
		}
		off += 16 + incl
		if off > size {
			break
		}
		p.Packets++
	}
	return p, nil
}

func parsePcapNG(ra io.ReaderAt, size int64, h []byte) (*Pcap, error) {
	p := &Pcap{Format: "pcapng"}
	var bo binary.ByteOrder
	switch binary.LittleEndian.Uint32(h[8:]) {
	case 0x1a2b3c4d:
		bo, p.LittleEndian = binary.LittleEndian, true
	case 0x4d3c2b1a:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("views: pcapng section header without byte-order magic")
	}
	p.VersionMajor, p.VersionMinor = bo.Uint16(h[12:]), bo.Uint16(h[14:])
	off := int64(0)
	blocks := 0
	for blocks < maxPcapWalk {
		bh, err := ReadRange(ra, size, off, 12)
		if err != nil || len(bh) < 8 {
			p.PacketsExact = err == nil && len(bh) == 0
			break
		}
		btype, blen := bo.Uint32(bh), int64(bo.Uint32(bh[4:]))
		if blen < 12 || blen%4 != 0 || off+blen > size {
			if blocks == 0 {
				return nil, fmt.Errorf("views: malformed pcapng section header")
			}
			break
		}
		switch btype {
		case 1: // interface description: link type in the first two bytes
			if p.LinkName == "" && len(bh) >= 12 {
				p.LinkType = uint32(bo.Uint16(bh[8:]))
				p.LinkName = linkTypes[p.LinkType]
				if b, err := ReadRange(ra, size, off+12, 4); err == nil && len(b) == 4 {
					p.SnapLen = bo.Uint32(b)
				}
			}
		case 3, 6: // simple / enhanced packet
			p.Packets++
		}
		off += blen
		blocks++
	}
	return p, nil
}
