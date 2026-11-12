package classify_test

import (
	"context"
	"slices"
	"testing"

	"github.com/craggy-io/foundation-kit/taxonomy"

	"github.com/craggy-io/classification-services/classify"
)

// An engine that joins a host's live taxonomy shares one graph with the
// other owners: its types are visible there, and its definitions can
// descend from a type someone else declared.
func TestSharedTaxonomy(t *testing.T) {
	ctx := context.Background()
	live := taxonomy.NewLive()
	if _, err := live.Declare("host", []taxonomy.Type{
		{Name: "container", Abstract: true},
		{Name: "container.layered", Parents: []string{"container"}},
	}); err != nil {
		t.Fatal(err)
	}

	e, err := classify.Open(ctx, t.TempDir(), classify.WithTaxonomy(live))
	if err != nil {
		t.Fatal(err)
	}
	shared := live.Taxonomy()
	if !shared.IsA("archive.jar", "archive.zip") || !slices.Equal(shared.Owners("archive.zip"), []string{classify.TaxonomyOwner}) {
		t.Fatal("the engine's types aren't in the live taxonomy")
	}
	if !e.IsA("container.layered", "container") {
		t.Fatal("the engine can't see another owner's types")
	}
	if host, ok := e.Type("container.layered"); !ok || host.MIME != "" {
		t.Fatalf("another owner's type = %+v, %v", host, ok)
	}

	// A definition whose parent the host declared, alongside a parent of
	// the engine's own.
	def := []byte(`type("acme", abstract = True)
type("acme.image", parents = ["acme", "container.layered", "archive.tar"])
`)
	if rep, err := e.Check(ctx, map[string][]byte{"acme": def}); err != nil || !rep.Passed() {
		t.Fatalf("Check = %+v, %v", rep, err)
	}
	if live.Taxonomy().Has("acme.image") {
		t.Fatal("Check published a type")
	}
	if _, err := e.Define(ctx, map[string][]byte{"acme": def}); err != nil {
		t.Fatal(err)
	}
	if got := live.Taxonomy(); !got.IsA("acme.image", "container") || !got.IsA("acme.image", "bytes") {
		t.Fatal("the defined type didn't reach the live taxonomy")
	}

	// The host can't withdraw a type the engine now builds on.
	if _, err := live.Withdraw("host"); err == nil {
		t.Fatal("the host withdrew a type a definition descends from")
	}

	// Another owner's change reaches the engine on Refresh.
	if _, err := live.Declare("java", []taxonomy.Type{{Name: "container.jvm", Parents: []string{"container", "archive.jar"}}}); err != nil {
		t.Fatal(err)
	}
	if e.IsA("container.jvm", "archive.zip") {
		t.Fatal("the engine changed without a Refresh")
	}
	if changed, err := e.Refresh(ctx); err != nil || !changed {
		t.Fatalf("Refresh = %v, %v", changed, err)
	}
	if !e.IsA("container.jvm", "archive.zip") {
		t.Fatal("Refresh didn't pick up the new type")
	}

	// Closing is refused while "java" builds on the engine's types, and
	// withdraws them once it doesn't.
	if err := e.Close(); err == nil {
		t.Fatal("Close withdrew types another owner descends from")
	}
	if _, err := live.Withdraw("java"); err != nil {
		t.Fatal(err)
	}
	e2, err := classify.Open(ctx, t.TempDir(), classify.WithTaxonomy(live))
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.Close(); err != nil {
		t.Fatal(err)
	}
	if got := live.Owners(); !slices.Equal(got, []string{"host"}) {
		t.Fatalf("owners after Close = %v", got)
	}
}

// Without a host taxonomy, a parent nobody in the engine declared is still
// an error.
func TestPrivateTaxonomyHasNoForeignTypes(t *testing.T) {
	e := open(t)
	_, err := e.Check(context.Background(), map[string][]byte{"acme": []byte(`type("acme.image", parents = ["container.layered"])`)})
	if err == nil {
		t.Fatal("an undeclared parent was accepted")
	}
}
