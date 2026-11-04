package cache_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/craggy-io/classification-services/internal/cache"
)

func TestImmutableEntriesStatAndMaintain(t *testing.T) {
	s, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Open(" "); err == nil {
		t.Fatal("blank workdir accepted")
	}
	s.Write("abcd", "keep.json", []byte("1"))
	s.Write("abcd", "keep.json", []byte("2")) // immutable: ignored
	s.Write("abcd", "drop.json", []byte("x"))
	if b, ok := s.Read("abcd", "keep.json"); !ok || string(b) != "1" {
		t.Fatalf("read = %q %v", b, ok)
	}
	f := filepath.Join(t.TempDir(), "f")
	os.WriteFile(f, []byte("data"), 0o644)
	fi, _ := os.Stat(f)
	s.StatStore(f, fi, "digest")
	if s.StatLookup(f, fi) != "digest" || len(s.KnownFiles(0)) != 1 {
		t.Fatal("stat index miss")
	}
	os.WriteFile(filepath.Join(s.SpoolDir(), "old"), nil, 0o644)
	past := time.Now().Add(-2 * time.Hour)
	os.Chtimes(filepath.Join(s.SpoolDir(), "old"), past, past)
	os.WriteFile(f, []byte("changed!"), 0o644)
	rep, err := s.Maintain(cache.Policy{KeepResult: func(n string) bool { return n == "keep.json" }})
	if err != nil || rep.ResultsRemoved != 1 || rep.ResultsKept != 1 || rep.StatRemoved != 1 || rep.SpoolRemoved != 1 {
		t.Fatalf("maintain = %+v %v", rep, err)
	}
	if _, ok := s.Read("abcd", "drop.json"); ok {
		t.Fatal("dropped entry still readable")
	}
}
