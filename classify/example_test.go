package classify_test

import (
	"context"
	"fmt"
	"os"

	"github.com/craggy-io/classification-services/classify"
	"github.com/craggy-io/classification-services/internal/testkit"
)

func ExampleEngine_Classify() {
	ctx := context.Background()
	workdir, _ := os.MkdirTemp("", "classify-example")
	defer os.RemoveAll(workdir)

	e, err := classify.Open(ctx, workdir)
	if err != nil {
		panic(err)
	}
	defer e.Close()

	jar := testkit.Zip(
		testkit.File{Name: "META-INF/MANIFEST.MF", Data: []byte("Main-Class: app.Main\n")},
		testkit.File{Name: "../../evil.sh", Data: []byte("#!/bin/sh\nid\n")},
	)
	r, err := e.Classify(ctx, classify.Bytes(jar).Named("app.jar"))
	if err != nil {
		panic(err)
	}
	fmt.Println(r.Primary, r.Is("archive.zip"))
	for _, a := range r.Anomalies {
		fmt.Println(a.Severity, a.Code)
	}
	for _, c := range r.Children {
		fmt.Println(c.Name, "->", c.Primary)
	}
	ex, _ := r.Explain("archive.jar")
	fmt.Print(ex)
	// Output:
	// archive.jar true
	// critical zip.path-traversal
	// META-INF/MANIFEST.MF -> text
	// ../../evil.sh -> source.shell
	// archive.jar holds (validated, direct), primary
	//   validated: asserted by classifier jar
	//   candidate: signature cyberchef:archive.jar.585a6da118aa matched 10 bytes at offset 0
}
