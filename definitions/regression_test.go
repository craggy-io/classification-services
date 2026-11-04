package definitions_test

import (
	"context"
	"testing"

	"github.com/craggy-io/classification-services/definitions"
)

func TestLoadRejectsDegenerateDeclarations(t *testing.T) {
	for _, bad := range []string{
		`signature("a.b", at(0, b""))`, // empty literal pattern
		`test("t")`,                    // no expectations
		`test("", expect = ["a.b"])`,   // empty test name
	} {
		if _, err := definitions.Load("bad", []byte(bad), nil); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLoadContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := "x = 0\nfor i in range(100000000):\n    x += i\n"
	if _, err := definitions.LoadContext(ctx, "slow", []byte(src), nil); err == nil {
		t.Fatal("cancelled load succeeded")
	}
}
