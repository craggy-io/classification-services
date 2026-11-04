package catalog_test

import (
	"testing"

	"github.com/craggy-io/classification-services/catalog"
)

func TestFingerprintDistinguishesFields(t *testing.T) {
	base := append(roots(),
		catalog.TypeInfo{Name: "a", Parents: []string{"bytes"}, Abstract: true},
		catalog.TypeInfo{Name: "a.x", Parents: []string{"a"}, Ext: []string{"p,q"}})
	c1, err := catalog.Build(base)
	if err != nil {
		t.Fatal(err)
	}
	variant := append(roots(),
		catalog.TypeInfo{Name: "a", Parents: []string{"bytes"}, Abstract: true},
		catalog.TypeInfo{Name: "a.x", Parents: []string{"a"}, Ext: []string{"p", "q"}})
	c2, err := catalog.Build(variant)
	if err != nil {
		t.Fatal(err)
	}
	if c1.TypeRevision("a.x") == c2.TypeRevision("a.x") {
		t.Fatal(`Ext ["p,q"] and ["p","q"] share a fingerprint`)
	}
	desc := append(roots(),
		catalog.TypeInfo{Name: "a", Parents: []string{"bytes"}, Abstract: true},
		catalog.TypeInfo{Name: "a.x", Parents: []string{"a"}, Ext: []string{"p,q"}, Description: "different"})
	c3, err := catalog.Build(desc)
	if err != nil {
		t.Fatal(err)
	}
	if c1.TypeRevision("a.x") == c3.TypeRevision("a.x") {
		t.Fatal("Description-only change keeps the fingerprint")
	}
	// The two definitions in one Build are a conflict, not a tolerant redeclare.
	if _, err := catalog.Build(append(base,
		catalog.TypeInfo{Name: "a.x", Parents: []string{"a"}, Ext: []string{"p", "q"}})); err == nil {
		t.Fatal("conflicting redeclaration accepted")
	}
}

func TestPermutedRedeclarationTolerated(t *testing.T) {
	infos := append(roots(),
		catalog.TypeInfo{Name: "a", Parents: []string{"bytes"}, Abstract: true},
		catalog.TypeInfo{Name: "a.x", Parents: []string{"a", "text"}, Ext: []string{"q", "p"}},
		catalog.TypeInfo{Name: "a.x", Parents: []string{"text", "a"}, Ext: []string{"p", "q"}},
	)
	if _, err := catalog.Build(infos); err != nil {
		t.Fatalf("permuted identical redeclaration rejected: %v", err)
	}
}

func TestIsAUndeclared(t *testing.T) {
	c, err := catalog.Build(roots())
	if err != nil {
		t.Fatal(err)
	}
	if c.IsA("bogus", "bogus") || c.IsA("", "") {
		t.Fatal("undeclared type IsA itself")
	}
	if !c.IsA("bytes", "bytes") {
		t.Fatal("declared type not IsA itself")
	}
}
