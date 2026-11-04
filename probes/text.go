package probes

import (
	"bytes"
	"context"
	"encoding/binary"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Text reports whether the content is UTF-8 text: valid UTF-8, no NUL and
// no control bytes other than tab, newline, CR, form feed and escape.
func Text(_ context.Context, in Input) ([]Finding, error) {
	if in.Size() == 0 {
		return nil, nil
	}
	b, err := in.Prefix(in.Limits().MaxBytes)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil // no sample read (e.g. MaxBytes == 0): nothing verified
	}
	whole := int64(len(b)) >= in.Size()
	if !isText(b, whole) {
		return nil, nil
	}
	level := Recognised
	if whole {
		level = Validated
	}
	return []Finding{Match("text", level, nil)}, nil
}

func isText(b []byte, whole bool) bool {
	if bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	if !whole {
		for i := 0; i < 3 && len(b) > 0 && !utf8.Valid(b); i++ {
			b = b[:len(b)-1] // a multi-byte rune cut by the read limit
		}
	}
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != 0x1b) || c == 0x7f {
			return false
		}
	}
	return true
}

// Charset recognises byte-order marks and BOM-less UTF-16 text, and derives
// the content transcoded to UTF-8 so it is classified as text in turn.
func Charset(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(4)
	if err != nil || len(head) < 2 {
		return nil, err
	}
	var typ string
	var skip int64
	switch {
	case len(head) >= 3 && bytes.Equal(head[:3], []byte{0xef, 0xbb, 0xbf}):
		return []Finding{Match("charset.utf8-bom", Validated, nil)}, nil
	case len(head) == 4 && bytes.Equal(head, []byte{0xff, 0xfe, 0, 0}):
		typ, skip = "charset.utf32le", 4
	case bytes.Equal(head[:2], []byte{0xff, 0xfe}):
		typ, skip = "charset.utf16le", 2
	case bytes.Equal(head[:2], []byte{0xfe, 0xff}):
		typ, skip = "charset.utf16be", 2
	}
	limit := min(in.Size(), in.Limits().MaxDerivedBytes, in.Limits().MaxBytes)
	if typ == "" {
		// BOM-less UTF-16: printable ASCII with a zero byte in every other
		// position over a reasonable sample.
		sample, err := in.Prefix(min(limit, 4096))
		if err != nil || len(sample) < 16 || len(sample)%2 != 0 {
			return nil, err
		}
		switch {
		case zeroStride(sample, 1):
			typ = "charset.utf16le"
		case zeroStride(sample, 0):
			typ = "charset.utf16be"
		default:
			return nil, nil
		}
	}
	b, err := in.Read(skip, limit-skip)
	if err != nil {
		return nil, err
	}
	var text string
	switch typ {
	case "charset.utf32le":
		var sb strings.Builder
		for i := 0; i+4 <= len(b); i += 4 {
			sb.WriteRune(rune(binary.LittleEndian.Uint32(b[i:])))
		}
		text = sb.String()
	default:
		var bo binary.ByteOrder = binary.LittleEndian
		if typ == "charset.utf16be" {
			bo = binary.BigEndian
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = bo.Uint16(b[2*i:])
		}
		text = string(utf16.Decode(u))
	}
	level := Validated
	if skip == 0 {
		level = Recognised
	}
	f := Match(typ, level, map[string]any{"bom": skip > 0})
	if data := []byte(text); int64(len(data)) <= in.Limits().MaxDerivedBytes {
		f.Children = []Derived{{Name: "utf-8", Data: data}}
	}
	return []Finding{f}, nil
}

func zeroStride(b []byte, zeroAt int) bool {
	for i := 0; i+1 < len(b); i += 2 {
		z, c := b[i+zeroAt], b[i+1-zeroAt]
		if z != 0 || c == 0 || c > 0x7e || (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
			return false
		}
	}
	return true
}

var shebangTypes = map[string]string{
	"sh": "source.shell", "dash": "source.shell", "ash": "source.shell", "zsh": "source.shell",
	"bash": "source.bash", "python": "source.python", "python2": "source.python", "python3": "source.python",
	"perl": "source.perl", "ruby": "source.ruby", "php": "source.php", "node": "source.node",
}

// Shebang recognises scripts by their "#!" interpreter line.
func Shebang(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(256)
	if err != nil || !bytes.HasPrefix(head, []byte("#!")) {
		return nil, err
	}
	line := string(head[2:])
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil, nil
	}
	interp := fields[0][strings.LastIndexByte(fields[0], '/')+1:]
	if interp == "env" && len(fields) > 1 {
		interp = fields[1]
		if strings.HasPrefix(interp, "-") && len(fields) > 2 {
			interp = fields[2]
		}
	}
	interp = strings.TrimRight(interp, "0123456789.")
	t, ok := shebangTypes[interp]
	if !ok {
		return nil, nil
	}
	return []Finding{Match(t, Recognised, map[string]any{"interpreter": strings.TrimSpace(line)})}, nil
}

var (
	javaPackageRe = regexp.MustCompile(`(?m)^\s*package\s+([a-zA-Z_][\w.]*)\s*;`)
	javaImportRe  = regexp.MustCompile(`(?m)^\s*import\s+(static\s+)?([a-zA-Z_][\w.]*\w)(\.\*)?\s*;`)
	javaClassRe   = regexp.MustCompile(`\b(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+|sealed\s+|static\s+)*(?:class|interface|enum|record)\s+([A-Z][A-Za-z0-9_]*)`)
)

// JavaSource recognises Java source heuristically: a type declaration plus
// a package or import statement.
func JavaSource(_ context.Context, in Input) ([]Finding, error) {
	text, err := in.Text(1 << 20)
	if err != nil {
		return nil, err
	}
	class := javaClassRe.FindStringSubmatch(text)
	if class == nil {
		return nil, nil
	}
	pkg := javaPackageRe.FindStringSubmatch(text)
	if pkg == nil && !javaImportRe.MatchString(text) {
		return nil, nil
	}
	md := map[string]any{"class_name": class[1]}
	if pkg != nil {
		md["package"] = pkg[1]
	}
	return []Finding{Match("source.java", Recognised, md)}, nil
}
