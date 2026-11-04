package catalog_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/craggy-io/classification-services/catalog"
)

func roots() []catalog.TypeInfo {
	return []catalog.TypeInfo{{Name: "bytes"}, {Name: "text", Parents: []string{"bytes"}}}
}

func TestBuildAndQuery(t *testing.T) {
	c, err := catalog.Build(append(roots(),
		catalog.TypeInfo{Name: "archive", Parents: []string{"bytes"}, Abstract: true},
		catalog.TypeInfo{Name: "archive.zip", Parents: []string{"archive"}, Ext: []string{".ZIP", "zip"}},
		catalog.TypeInfo{Name: "archive.jar", Parents: []string{"archive.zip", "archive.zip"}},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsA("archive.jar", "bytes") || !c.IsA("archive.jar", "archive.jar") || c.IsA("archive.zip", "archive.jar") {
		t.Fatal("IsA wrong")
	}
	if !slices.Equal(c.Ancestors("archive.jar"), []string{"archive", "archive.zip", "bytes"}) || c.Depth("archive.jar") != 3 {
		t.Fatalf("ancestors = %v depth = %d", c.Ancestors("archive.jar"), c.Depth("archive.jar"))
	}
	if got := c.ByExtension(".zip"); !slices.Equal(got, []string{"archive.zip"}) {
		t.Fatalf("ByExtension = %v", got)
	}
	jar, _ := c.Get("archive.jar")
	if len(jar.Parents) != 1 {
		t.Fatalf("duplicate parent kept: %v", jar.Parents)
	}
	c2, _ := catalog.Build(append(roots(), catalog.TypeInfo{Name: "archive", Parents: []string{"bytes"}, Abstract: true},
		catalog.TypeInfo{Name: "archive.zip", Parents: []string{"archive"}, Ext: []string{"zip"}, MIME: "application/zip"},
		catalog.TypeInfo{Name: "archive.jar", Parents: []string{"archive.zip"}}))
	if c.Revision() == c2.Revision() || c.TypeRevision("archive.jar") != c2.TypeRevision("archive.jar") || c.TypeRevision("archive.zip") == c2.TypeRevision("archive.zip") {
		t.Fatal("revisions do not track content")
	}
}

func TestBuildErrors(t *testing.T) {
	for want, extra := range map[string][]catalog.TypeInfo{
		"unknown parent":    {{Name: "a.b", Parents: []string{"nope"}}},
		"cycle":             {{Name: "a.x", Parents: []string{"a.y"}}, {Name: "a.y", Parents: []string{"a.x"}}},
		"redeclared":        {{Name: "a.x", Parents: []string{"bytes"}}, {Name: "a.x", Parents: []string{"text"}}},
		"does not descend":  {{Name: "a", Parents: []string{"bytes"}}, {Name: "a.x", Parents: []string{"text"}}},
		"invalid type name": {{Name: "Upper.Case", Parents: []string{"bytes"}}},
		"has no parents":    {{Name: "lonely"}},
	} {
		_, err := catalog.Build(append(roots(), extra...))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v", want, err)
		}
	}
}
