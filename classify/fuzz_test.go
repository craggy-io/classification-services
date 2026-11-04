package classify_test

import (
	"context"
	"testing"

	"github.com/craggy-io/classification-services/classify"
	"github.com/craggy-io/classification-services/internal/testkit"
)

func FuzzClassifyNeverPanics(f *testing.F) {
	f.Add(testkit.Zip(testkit.File{Name: "AndroidManifest.xml", Data: testkit.AXML("a", true)}))
	f.Add(testkit.Gzip(testkit.Tar(testkit.File{Name: "a", Data: []byte("{}")}), "t"))
	f.Add(append(testkit.ELF(128), testkit.Zip(testkit.File{Name: "x", Data: []byte("x")})...))
	f.Add([]byte("%PDF-1.7 /JavaScript %%EOF"))
	f.Add([]byte("aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ="))
	e, err := classify.Open(context.Background(), f.TempDir(), classify.WithLimits(classify.Limits{MaxNodes: 200, MaxDerivedBytes: 4 << 20}))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := e.Classify(context.Background(), classify.Bytes(b), classify.WithDepth(classify.Deep))
		if err != nil {
			t.Fatal(err)
		}
		if !r.Is("bytes") || r.Primary == "" {
			t.Fatalf("result without root: %+v", r)
		}
	})
}

func FuzzDefineNeverPanics(f *testing.F) {
	f.Add(widgetDef)
	f.Add(`type("x.y", parents = ["x.y"])`)
	f.Add("def f(ctx):\n    return ctx.match(1)\nclassifier(\"f\", run = f)")
	e, err := classify.Open(context.Background(), f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, src string) {
		e.Check(context.Background(), "fuzz", []byte(src))
	})
}
