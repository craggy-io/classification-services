package artifactsvc_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/craggy-io/artifact-services/artifacts"
	"github.com/craggy-io/artifact-services/observability"

	"github.com/craggy-io/classification-services/adapters/artifactsvc"
	"github.com/craggy-io/classification-services/classify"
)

// fakeStore is a Store whose manifest size and pagination can lie.
type fakeStore struct {
	data   []byte
	size   int64
	cursor string // NextCursor returned by every ListFiles call
}

func (f *fakeStore) Publish(context.Context, artifacts.Manifest) (artifacts.ID, error) {
	return "", errors.New("unused")
}
func (f *fakeStore) Get(context.Context, artifacts.ID) (artifacts.Manifest, error) {
	return artifacts.Manifest{}, errors.New("unused")
}
func (f *fakeStore) OpenFile(context.Context, artifacts.ID, string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.data)), nil
}
func (f *fakeStore) ListFiles(_ context.Context, _ artifacts.ID, q artifacts.FileQuery) (artifacts.FilePage, error) {
	if q.Cursor != "" && f.cursor == "" {
		return artifacts.FilePage{}, nil
	}
	return artifacts.FilePage{
		Entries:    []artifacts.Entry{{Path: "a.json", Size: f.size}},
		NextCursor: f.cursor,
	}, nil
}
func (f *fakeStore) Search(context.Context, artifacts.CatalogQuery) (artifacts.CatalogPage, error) {
	return artifacts.CatalogPage{}, errors.New("unused")
}
func (f *fakeStore) Category(context.Context, artifacts.ID) (observability.Category, error) {
	return 0, errors.New("unused")
}

func openEngine(t *testing.T) *classify.Engine {
	t.Helper()
	e, err := classify.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestLyingManifestSizeRejected(t *testing.T) {
	data := []byte(`{"x": 1}`)
	c := &artifactsvc.Classifier{Engine: openEngine(t), Artifacts: &fakeStore{data: data, size: 1}}
	rep, err := c.ClassifyArtifact(context.Background(), "a1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Files) != 1 || rep.Files[0].Error == "" || rep.Files[0].Result != nil {
		t.Fatalf("report = %+v, want a per-file size error", rep.Files)
	}
}

func TestStuckCursorErrors(t *testing.T) {
	data := []byte(`{}`)
	c := &artifactsvc.Classifier{Engine: openEngine(t), Artifacts: &fakeStore{data: data, size: int64(len(data)), cursor: "again"}}
	if _, err := c.ClassifyArtifact(context.Background(), "a1"); err == nil {
		t.Fatal("non-advancing cursor accepted")
	}
}

func TestPerCallDepthReported(t *testing.T) {
	data := []byte(`{}`)
	c := &artifactsvc.Classifier{Engine: openEngine(t), Artifacts: &fakeStore{data: data, size: int64(len(data))}, Depth: classify.Standard}
	rep, err := c.ClassifyArtifact(context.Background(), "a1", classify.WithDepth(classify.Deep))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Depth != classify.Deep {
		t.Fatalf("depth = %s, want deep", rep.Depth)
	}
}

func TestPublishNilReport(t *testing.T) {
	c := &artifactsvc.Classifier{}
	if _, err := c.Publish(context.Background(), nil); err == nil {
		t.Fatal("nil report accepted")
	}
}
