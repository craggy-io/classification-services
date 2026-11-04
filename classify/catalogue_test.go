package classify_test

import (
	"strings"
	"testing"

	"github.com/craggy-io/classification-services/catalog"
)

// The built-in catalogue follows the clean-break naming scheme: every type
// other than the two roots is "namespace.name" under a declared, abstract
// namespace type, and every concrete type has a description.
func TestBuiltinCatalogueConventions(t *testing.T) {
	e := open(t)
	cat := e.Catalog()
	for _, ti := range e.Types() {
		switch {
		case ti.Name == catalog.Bytes || ti.Name == catalog.Text:
			continue
		case !strings.Contains(ti.Name, "."):
			if !ti.Abstract {
				t.Errorf("namespace %q is not abstract", ti.Name)
			}
			continue
		}
		ns := catalog.Namespace(ti.Name)
		info, ok := cat.Get(ns)
		if !ok || !info.Abstract {
			t.Errorf("%s: namespace %q missing or not abstract", ti.Name, ns)
		}
		if ti.Description == "" {
			t.Errorf("%s has no description", ti.Name)
		}
	}
	if cat.Len() < 180 {
		t.Fatalf("catalogue has only %d types", cat.Len())
	}
}
