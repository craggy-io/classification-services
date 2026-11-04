package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// JSON validates the content as exactly one JSON value.
func JSON(_ context.Context, in Input) ([]Finding, error) {
	v, err := in.JSON(in.Limits().MaxBytes)
	if err != nil {
		return nil, nil
	}
	md := map[string]any{}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 100 {
			keys = keys[:100]
		}
		md["kind"], md["keys"], md["key_count"] = "object", keys, len(t)
	case []any:
		md["kind"], md["length"] = "array", len(t)
	case string:
		md["kind"] = "string"
	case bool:
		md["kind"] = "bool"
	case json.Number:
		md["kind"] = "number"
	case nil:
		md["kind"] = "null"
	default:
		md["kind"] = fmt.Sprintf("%T", v)
	}
	level := Validated
	if in.Size() > in.Limits().MaxBytes {
		level = Recognised // only a prefix was decoded; the tail is unverified
	}
	return []Finding{Match("data.json", level, md)}, nil
}

// XML validates well-formed XML with a single root element. SVG and XML
// property lists are recognised from the root element.
func XML(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(512)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(head, []byte{0xef, 0xbb, 0xbf}), " \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("<")) {
		return nil, nil
	}
	text, err := in.Text(in.Limits().MaxBytes)
	if err != nil {
		return nil, err
	}
	dec := xml.NewDecoder(strings.NewReader(text))
	dec.Strict = true
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	var root string
	depth, elements := 0, 0
	closed := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if root != "" && int64(len(text)) >= in.Size() {
				return []Finding{Reject("data.xml", Validated)}, nil
			}
			return nil, nil
		}
		switch t := tok.(type) {
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				if root != "" {
					return []Finding{Reject("data.xml", Validated)}, nil // junk outside the root
				}
				return nil, nil
			}
		case xml.StartElement:
			if closed {
				return []Finding{Reject("data.xml", Validated)}, nil // second root
			}
			if root == "" {
				root = t.Name.Local
			}
			depth++
			elements++
		case xml.EndElement:
			depth--
			if depth == 0 {
				closed = true
			}
		}
	}
	if root == "" || !closed {
		return nil, nil
	}
	level := Validated
	if int64(len(text)) < in.Size() {
		level = Recognised // truncated read: bytes past the cap are unverified
	}
	md := map[string]any{"root": root, "elements": elements}
	out := []Finding{Match("data.xml", level, md)}
	switch root {
	case "svg":
		out = append(out, Match("image.svg", level, md))
	case "plist":
		out = append(out, Match("data.plist-xml", level, md))
	}
	return out, nil
}

// SQLite validates a SQLite 3 database header.
func SQLite(_ context.Context, in Input) ([]Finding, error) {
	hdr, err := in.Prefix(100)
	if err != nil {
		return nil, err
	}
	const magic = "SQLite format 3\x00"
	if len(hdr) < 100 || !bytes.HasPrefix(hdr, []byte(magic)) {
		if bytes.HasPrefix(hdr, []byte("SQLite format 3")) {
			return []Finding{Reject("data.sqlite", Validated)}, nil
		}
		return nil, nil
	}
	be := binary.BigEndian
	page := int64(be.Uint16(hdr[16:]))
	if page == 1 {
		page = 65536
	}
	if page < 512 || page > 65536 || page&(page-1) != 0 {
		return []Finding{Reject("data.sqlite", Validated)}, nil
	}
	enc := map[uint32]string{1: "utf-8", 2: "utf-16le", 3: "utf-16be"}[be.Uint32(hdr[56:])]
	if enc == "" {
		enc = "unknown"
	}
	return []Finding{Match("data.sqlite", Validated, map[string]any{
		"page_size": page, "page_count": int64(be.Uint32(hdr[28:])),
		"schema_cookie": int64(be.Uint32(hdr[40:])), "encoding": enc,
	})}, nil
}
