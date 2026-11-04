package views

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"unicode/utf16"
)

// AXML is a parsed Android binary XML document (the compiled form of
// AndroidManifest.xml and res/*.xml inside an APK).
type AXML struct {
	Elements []AXMLElement
}

// AXMLElement is one start tag with its attributes rendered as strings.
type AXMLElement struct {
	Name  string
	Depth int
	Attrs map[string]string
}

// Manifest is the security-relevant summary of an AndroidManifest.xml.
type Manifest struct {
	Package     string
	VersionCode string
	VersionName string
	MinSDK      string
	TargetSDK   string
	Permissions []string
	Debuggable  bool
	AllowBackup bool
	// Exported lists components ("activity:com.example.Main") declared with
	// android:exported="true".
	Exported   []string
	Components int
}

const (
	maxAXMLBytes    = 8 << 20
	maxAXMLStrings  = 1 << 18
	maxAXMLElements = 1 << 16
)

// Well-known android: attribute resource IDs, used when obfuscators strip
// attribute names from the string pool.
var axmlAttrIDs = map[uint32]string{
	0x01010003: "name", 0x0101021b: "versionCode", 0x0101021c: "versionName",
	0x0101020c: "minSdkVersion", 0x01010270: "targetSdkVersion", 0x0101000f: "debuggable",
	0x01010280: "allowBackup", 0x01010010: "exported", 0x01010001: "label", 0x01010002: "icon",
	0x01010006: "permission",
}

// ParseAXMLAt reads a whole (bounded) input as binary XML.
func ParseAXMLAt(ra io.ReaderAt, size int64) (*AXML, error) {
	if size > maxAXMLBytes {
		return nil, fmt.Errorf("views: binary XML of %d bytes exceeds %d", size, maxAXMLBytes)
	}
	b, err := readExact(ra, size, 0, size)
	if err != nil {
		return nil, err
	}
	return ParseAXML(b)
}

// ParseAXML parses Android binary XML.
func ParseAXML(b []byte) (*AXML, error) {
	le := binary.LittleEndian
	if len(b) < 8 || le.Uint16(b) != 0x0003 {
		return nil, fmt.Errorf("views: not Android binary XML")
	}
	total := int(le.Uint32(b[4:]))
	if total > len(b) || total < 8 {
		total = len(b)
	}
	var pool []string
	var resIDs []uint32
	doc := &AXML{}
	depth := 0
	str := func(i uint32) string {
		if int64(i) < int64(len(pool)) {
			return pool[i]
		}
		return ""
	}
	for off := int(le.Uint16(b[2:])); off+8 <= total; {
		ctype := le.Uint16(b[off:])
		hsize := int(le.Uint16(b[off+2:]))
		csize := int(le.Uint32(b[off+4:]))
		if csize < 8 || off+csize > total || hsize > csize {
			return nil, fmt.Errorf("views: malformed binary XML chunk at %d", off)
		}
		chunk := b[off : off+csize]
		switch ctype {
		case 0x0001:
			p, err := parseStringPool(chunk)
			if err != nil {
				return nil, err
			}
			pool = p
		case 0x0180:
			for i := hsize; i+4 <= len(chunk); i += 4 {
				resIDs = append(resIDs, le.Uint32(chunk[i:]))
			}
		case 0x0102:
			if len(chunk) < hsize+20 {
				return nil, fmt.Errorf("views: short binary XML element")
			}
			ext := chunk[hsize:]
			el := AXMLElement{Name: str(le.Uint32(ext[4:])), Depth: depth, Attrs: map[string]string{}}
			attrStart := int(le.Uint16(ext[8:]))
			attrSize := int(le.Uint16(ext[10:]))
			attrCount := int(le.Uint16(ext[12:]))
			if attrSize < 20 {
				attrSize = 20
			}
			for i := 0; i < attrCount; i++ {
				a := hsize + attrStart + i*attrSize
				if a+20 > len(chunk) {
					break
				}
				nameIdx := le.Uint32(chunk[a+4:])
				name := str(nameIdx)
				if name == "" && int64(nameIdx) < int64(len(resIDs)) {
					name = axmlAttrIDs[resIDs[nameIdx]]
				}
				if name == "" {
					name = "attr" + strconv.Itoa(i)
				}
				raw := le.Uint32(chunk[a+8:])
				dtype := chunk[a+15]
				data := le.Uint32(chunk[a+16:])
				el.Attrs[name] = axmlValue(dtype, data, raw, str)
			}
			doc.Elements = append(doc.Elements, el)
			if len(doc.Elements) > maxAXMLElements {
				return nil, fmt.Errorf("views: binary XML exceeds %d elements", maxAXMLElements)
			}
			depth++
		case 0x0103:
			depth = max(depth-1, 0)
		}
		off += csize
	}
	if len(doc.Elements) == 0 {
		return nil, fmt.Errorf("views: binary XML without elements")
	}
	return doc, nil
}

func axmlValue(dtype byte, data, raw uint32, str func(uint32) string) string {
	switch dtype {
	case 0x03:
		return str(data)
	case 0x10:
		return strconv.FormatInt(int64(int32(data)), 10)
	case 0x11:
		return "0x" + strconv.FormatUint(uint64(data), 16)
	case 0x12:
		return strconv.FormatBool(data != 0)
	case 0x01:
		return "@0x" + strconv.FormatUint(uint64(data), 16)
	}
	if raw != 0xffffffff {
		return str(raw)
	}
	return strconv.FormatUint(uint64(data), 10)
}

func parseStringPool(c []byte) ([]string, error) {
	le := binary.LittleEndian
	if len(c) < 28 {
		return nil, fmt.Errorf("views: short string pool")
	}
	hsize := int(le.Uint16(c[2:]))
	count := int(le.Uint32(c[8:]))
	utf8 := le.Uint32(c[16:])&(1<<8) != 0
	start := int(le.Uint32(c[20:]))
	if count > maxAXMLStrings || hsize+count*4 > len(c) {
		return nil, fmt.Errorf("views: string pool count %d out of range", count)
	}
	out := make([]string, count)
	for i := 0; i < count; i++ {
		p := start + int(le.Uint32(c[hsize+i*4:]))
		if p < 0 || p >= len(c) {
			continue
		}
		if utf8 {
			// utf16 length (1-2 bytes), utf8 length (1-2 bytes), bytes.
			_, n1 := axmlLen8(c, p)
			l, n2 := axmlLen8(c, p+n1)
			s := p + n1 + n2
			if n1 == 0 || n2 == 0 || s+l > len(c) {
				continue
			}
			out[i] = string(c[s : s+l])
		} else {
			l, n := axmlLen16(c, p)
			s := p + n
			if n == 0 || s+2*l > len(c) {
				continue
			}
			u := make([]uint16, l)
			for j := range u {
				u[j] = le.Uint16(c[s+2*j:])
			}
			out[i] = string(utf16.Decode(u))
		}
	}
	return out, nil
}

func axmlLen8(c []byte, p int) (int, int) {
	if p >= len(c) {
		return 0, 0
	}
	if c[p]&0x80 == 0 {
		return int(c[p]), 1
	}
	if p+1 >= len(c) {
		return 0, 0
	}
	return int(c[p]&0x7f)<<8 | int(c[p+1]), 2
}

func axmlLen16(c []byte, p int) (int, int) {
	le := binary.LittleEndian
	if p+2 > len(c) {
		return 0, 0
	}
	v := int(le.Uint16(c[p:]))
	if v&0x8000 == 0 {
		return v, 2
	}
	if p+4 > len(c) {
		return 0, 0
	}
	return (v&0x7fff)<<16 | int(le.Uint16(c[p+2:])), 4
}

// Manifest summarises an AndroidManifest.xml document.
func (x *AXML) Manifest() (*Manifest, error) {
	if len(x.Elements) == 0 || x.Elements[0].Name != "manifest" {
		return nil, fmt.Errorf("views: binary XML root is not <manifest>")
	}
	root := x.Elements[0].Attrs
	m := &Manifest{Package: root["package"], VersionCode: root["versionCode"], VersionName: root["versionName"]}
	for _, el := range x.Elements[1:] {
		switch el.Name {
		case "uses-permission", "uses-permission-sdk-23":
			if n := el.Attrs["name"]; n != "" {
				m.Permissions = append(m.Permissions, n)
			}
		case "uses-sdk":
			m.MinSDK, m.TargetSDK = el.Attrs["minSdkVersion"], el.Attrs["targetSdkVersion"]
		case "application":
			m.Debuggable = el.Attrs["debuggable"] == "true"
			m.AllowBackup = el.Attrs["allowBackup"] != "false" // defaults to true
		case "activity", "activity-alias", "service", "receiver", "provider":
			m.Components++
			if el.Attrs["exported"] == "true" {
				m.Exported = append(m.Exported, el.Name+":"+el.Attrs["name"])
			}
		}
	}
	return m, nil
}

// Describe implements Describer.
func (x *AXML) Describe() map[string]any {
	out := map[string]any{"elements": int64(len(x.Elements))}
	if len(x.Elements) > 0 {
		out["root"] = x.Elements[0].Name
	}
	if m, err := x.Manifest(); err == nil {
		out["package"] = m.Package
		out["version_code"] = m.VersionCode
		out["version_name"] = m.VersionName
		out["min_sdk"] = m.MinSDK
		out["target_sdk"] = m.TargetSDK
		out["permissions"] = strs(m.Permissions)
		out["debuggable"] = m.Debuggable
		out["allow_backup"] = m.AllowBackup
		out["exported"] = strs(m.Exported)
		out["components"] = int64(m.Components)
	}
	return out
}
