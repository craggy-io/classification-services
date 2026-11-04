package artifactsvc_test

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/craggy-io/artifact-services/artifacts"
	"github.com/craggy-io/artifact-services/cas"
	"github.com/craggy-io/artifact-services/lineage"
	"github.com/craggy-io/artifact-services/objects"
	"github.com/craggy-io/artifact-services/observability"
	"github.com/craggy-io/artifact-services/provenance"
	"github.com/craggy-io/artifact-services/storage"

	"github.com/craggy-io/classification-services/adapters/artifactsvc"
	"github.com/craggy-io/classification-services/classify"
	"github.com/craggy-io/classification-services/internal/testkit"
)

func TestClassifyPublishAndRecord(t *testing.T) {
	root := t.TempDir()
	metrics := new(observability.Collector)
	ctx := observability.With(context.Background(), observability.Options{Collector: metrics})

	blobs, err := storage.NewFilesystem(filepath.Join(root, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := cas.New(blobs, cas.Options{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifacts.New(content, artifacts.Options{Root: filepath.Join(root, "catalog"), IndexedMetadata: []string{"kind"}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	typed, err := objects.New(content, store, objects.Options{})
	if err != nil {
		t.Fatal(err)
	}
	history, err := lineage.New(store, lineage.Options{Root: filepath.Join(root, "lineage"), ValidateSelector: typed.ValidateRef})
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	engine, err := classify.Open(ctx, filepath.Join(root, "classify"))
	if err != nil {
		t.Fatal(err)
	}

	// An artifact with an APK and a ZIP that escapes its root.
	apk := testkit.Zip(testkit.File{Name: "AndroidManifest.xml", Data: testkit.AXML("com.example", true)})
	evil := testkit.Zip(testkit.File{Name: "../../x", Data: []byte("x")})
	var entries []artifacts.Entry
	for path, data := range map[string][]byte{"app.apk": apk, "bundle.zip": evil} {
		put, err := content.Put(ctx, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, artifacts.Entry{Path: path, Content: put.ID, Size: put.Size})
	}
	input, err := store.Publish(ctx, artifacts.Manifest{Version: 1, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}

	c := &artifactsvc.Classifier{Engine: engine, Artifacts: store, CAS: content, Objects: typed, Lineage: history}
	rep, err := c.ClassifyArtifact(ctx, input, classify.Observe(artifactsvc.Observer(ctx)))
	if err != nil {
		t.Fatal(err)
	}
	primaries := map[string]string{}
	for _, f := range rep.Files {
		if f.Error != "" {
			t.Fatalf("%s: %s", f.Path, f.Error)
		}
		primaries[f.Path] = f.Result.Primary
	}
	if primaries["app.apk"] != "android.apk" || primaries["bundle.zip"] != "archive.zip" {
		t.Fatalf("primaries = %v", primaries)
	}

	pub, err := c.Publish(ctx, rep)
	if err != nil {
		t.Fatalf("publish: %v (stored %+v)", err, pub)
	}
	if pub.Report == "" || pub.Types == "" || pub.Anomalies == "" || pub.Activity == "" || pub.AnomaliesRevision == "" {
		t.Fatalf("published = %+v", pub)
	}
	// Re-publishing is an idempotent lineage retry.
	if again, err := c.Publish(ctx, rep); err != nil || again.Activity != pub.Activity {
		t.Fatalf("republish = %+v, %v", again, err)
	}

	// The anomalies table is queryable with sql-v1.
	stream, err := typed.Query(ctx, objects.QueryRequest{
		Language:   objects.SQL,
		Text:       "SELECT path, code FROM a WHERE severity = :sev",
		Parameters: map[string]any{"sev": "critical"},
		Inputs:     []objects.Input{{Alias: "a", Artifact: pub.Anomalies, Revision: string(pub.AnomaliesRevision)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var crit []string
	for {
		row, err := stream.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		crit = append(crit, row.Values["path"].(string)+" "+row.Values["code"].(string))
	}
	if len(crit) != 1 || crit[0] != "bundle.zip zip.path-traversal" {
		t.Fatalf("critical anomalies = %v", crit)
	}

	// Lineage links the input artifact to the report.
	page, err := history.List(ctx, lineage.Query{ActivityKind: "classification", Ref: &provenance.Ref{Artifact: string(input)}, Role: "input"})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("lineage = %+v, %v", page, err)
	}

	// The bridge reported classification spans to the shared collector.
	seen := map[string]uint64{}
	for scope, m := range metrics.Snapshot(observability.SnapshotOptions{}) {
		if scope.Layer == artifactsvc.Layer {
			seen[scope.Operation] += m.Started
		}
	}
	if seen["classify"] != 2 || seen["node"] == 0 || seen["classifier"] != 0 {
		t.Fatalf("classification spans (user-visible) = %v", seen)
	}
}
