package signatures_test

import (
	"testing"

	"github.com/craggy-io/classification-services/defs"
	"github.com/craggy-io/classification-services/signatures"
)

func TestHexAndMatcher(t *testing.T) {
	zip, err := signatures.Hex(0, "50 4b ?? 04")
	if err != nil {
		t.Fatal(err)
	}
	trailer := signatures.Literal(6, []byte("XY"))
	m, err := signatures.New([]signatures.Rule{
		{ID: "zip", Type: "archive.zip", Patterns: []signatures.Pattern{zip}},
		{ID: "two", Type: "acme.two", Patterns: []signatures.Pattern{zip, trailer}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hits := m.Match([]byte("PK\x03\x04..XY"), 8)
	if len(hits) != 2 || hits[0].Rule != "zip" || hits[1].Length != 8 {
		t.Fatalf("hits = %+v", hits)
	}
	if hits := m.Match([]byte("PK\x03\x05"), 4); len(hits) != 0 {
		t.Fatalf("mismatch hit: %+v", hits)
	}
	if hits := m.Match([]byte("PK\x03\x04..XY"), 7); len(hits) != 1 {
		t.Fatalf("pattern beyond size matched: %+v", hits)
	}
	for _, bad := range []string{"", "abc", "zz", "5?"} {
		if _, err := signatures.Hex(0, bad); err == nil {
			t.Errorf("Hex(%q) accepted", bad)
		}
	}
}

func TestCyberChefSet(t *testing.T) {
	rules, file, err := signatures.ParseCyberChef(defs.CyberChef(), "cyberchef")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Rules) != 141 || len(rules) < 141 {
		t.Fatalf("rules = %d (file %d)", len(rules), len(file.Rules))
	}
	m, err := signatures.New(rules)
	if err != nil {
		t.Fatal(err)
	}
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 'J', 'F', 'I', 'F', 0}
	prefix := append(jpeg, make([]byte, m.MaxEnd())...)
	found := false
	for _, h := range m.Match(prefix, int64(len(prefix))) {
		found = found || h.Type == "image.jpeg"
	}
	if !found {
		t.Fatal("JPEG signature did not fire")
	}
}
