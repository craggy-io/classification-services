// Package cache owns the workdir layout:
//
//	<workdir>/
//	  definitions/classify.installed/ the bundle Define installs into
//	    bundle.yaml                   its manifest, rewritten by Define/Remove
//	    <name>.star                   one module per Define
//	  cache/stat/                     (abs path, size, mtime) -> digest
//	  cache/results/<ab>/<digest>/    one immutable file per cache key
//	    <classifier>@<rev>.json       a classifier's output for that content
//	    node@<profile>.json           a whole classification result
//	  spool/                          large derived children, deleted after use
//
// Every entry is written to a temp file and renamed into place, and entries
// are immutable once written. Two processes sharing a workdir can at worst
// duplicate work; they cannot corrupt each other. There is no lock file and
// no single-writer database.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/craggy-io/foundation-kit/fsx"
)

// Store is a workdir. It holds no open handles, so it needs no Close.
type Store struct {
	root string
}

// Open prepares the layout under root, which must be non-empty.
func Open(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("cache: workdir is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("cache: resolving workdir: %w", err)
	}
	s := &Store{root: abs}
	for _, d := range []string{s.DefinitionsDir(), s.dir("stat"), s.dir("results"), s.SpoolDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("cache: creating workdir: %w", err)
		}
	}
	return s, nil
}

// Root is the absolute workdir.
func (s *Store) Root() string { return s.root }

// DefinitionsDir is the install folder for bundle.Live: it holds the
// bundle of runtime-defined modules.
func (s *Store) DefinitionsDir() string { return filepath.Join(s.root, "definitions") }

// SpoolDir holds temporary files for large derived children.
func (s *Store) SpoolDir() string { return filepath.Join(s.root, "spool") }

func (s *Store) dir(name string) string { return filepath.Join(s.root, "cache", name) }

func (s *Store) resultDir(digest string) string {
	shard := "xx"
	if len(digest) >= 2 {
		shard = digest[:2]
	}
	return filepath.Join(s.dir("results"), shard, digest)
}

// SafeName maps an identifier onto a portable file-name component.
func SafeName(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

// ClassifierFile is the entry name for a classifier's output.
func ClassifierFile(id, rev string) string { return SafeName(id) + "@" + rev + ".json" }

// NodeFile is the entry name for a whole-result profile.
func NodeFile(profile string) string { return "node@" + SafeName(profile) + ".json" }

// Read returns an entry for digest, if present.
func (s *Store) Read(digest, file string) ([]byte, bool) {
	b, err := os.ReadFile(filepath.Join(s.resultDir(digest), file))
	return b, err == nil
}

// Write stores an immutable entry for digest.
func (s *Store) Write(digest, file string, data []byte) error {
	return WriteImmutable(filepath.Join(s.resultDir(digest), file), data)
}

// --- stat index ---

type statEntry struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	MtimeNano int64  `json:"mtime_ns"`
	Digest    string `json:"digest"`
}

func (s *Store) statPath(abs string) string {
	h := sha256.Sum256([]byte(abs))
	return filepath.Join(s.dir("stat"), hex.EncodeToString(h[:])+".json")
}

// StatLookup returns the digest recorded for an unchanged file, or "".
func (s *Store) StatLookup(abs string, fi os.FileInfo) string {
	b, err := os.ReadFile(s.statPath(abs))
	if err != nil {
		return ""
	}
	var e statEntry
	if json.Unmarshal(b, &e) != nil || e.Path != abs || e.Size != fi.Size() || e.MtimeNano != fi.ModTime().UnixNano() {
		return ""
	}
	return e.Digest
}

// StatStore records a file's digest. Entries are replaceable.
func (s *Store) StatStore(abs string, fi os.FileInfo, digest string) {
	b, err := json.Marshal(statEntry{Path: abs, Size: fi.Size(), MtimeNano: fi.ModTime().UnixNano(), Digest: digest})
	if err == nil {
		_ = ReplaceFile(s.statPath(abs), b)
	}
}

// KnownFile is a file recorded in the stat index that is still unchanged.
type KnownFile struct {
	Path   string
	Digest string
}

// KnownFiles lists up to limit indexed files whose size and mtime still
// match, so their recorded digest is still the content's.
func (s *Store) KnownFiles(limit int) []KnownFile {
	entries, err := os.ReadDir(s.dir("stat"))
	if err != nil {
		return nil
	}
	var out []KnownFile
	for _, ent := range entries {
		if limit > 0 && len(out) >= limit {
			break
		}
		b, err := os.ReadFile(filepath.Join(s.dir("stat"), ent.Name()))
		if err != nil {
			continue
		}
		var e statEntry
		if json.Unmarshal(b, &e) != nil {
			continue
		}
		if fi, err := os.Stat(e.Path); err == nil && fi.Size() == e.Size && fi.ModTime().UnixNano() == e.MtimeNano {
			out = append(out, KnownFile{Path: e.Path, Digest: e.Digest})
		}
	}
	return out
}

// --- maintenance ---

// Report summarises one maintenance pass.
type Report struct {
	ResultsRemoved int `json:"results_removed"`
	ResultsKept    int `json:"results_kept"`
	StatRemoved    int `json:"stat_removed"`
	SpoolRemoved   int `json:"spool_removed"`
	TempRemoved    int `json:"temp_removed"`
}

// Policy says which entries a maintenance pass keeps.
type Policy struct {
	KeepResult func(file string) bool // file is an entry name (ClassifierFile/NodeFile)
	// StaleAfter is the age beyond which spool and temp files are orphaned
	// leftovers of an interrupted process. Zero selects one hour.
	StaleAfter time.Duration
}

// Maintain removes cache entries the policy no longer keeps, stat entries
// for files that changed or vanished, and stale spool/temp files.
func (s *Store) Maintain(p Policy) (Report, error) {
	var rep Report
	stale := p.StaleAfter
	if stale <= 0 {
		stale = time.Hour
	}
	cutoff := time.Now().Add(-stale)
	old := func(d fs.DirEntry) bool {
		fi, err := d.Info()
		return err == nil && fi.ModTime().Before(cutoff)
	}
	err := filepath.WalkDir(s.dir("results"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		switch {
		case strings.HasPrefix(name, ".tmp-"):
			if old(d) && os.Remove(path) == nil {
				rep.TempRemoved++
			}
		case p.KeepResult != nil && !p.KeepResult(name):
			if os.Remove(path) == nil {
				rep.ResultsRemoved++
			}
		default:
			rep.ResultsKept++
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	removeEmptyDirs(s.dir("results"))
	if ents, err := os.ReadDir(s.dir("stat")); err == nil {
		for _, ent := range ents {
			path := filepath.Join(s.dir("stat"), ent.Name())
			b, err := os.ReadFile(path)
			var e statEntry
			if err != nil || json.Unmarshal(b, &e) != nil {
				continue
			}
			if fi, err := os.Stat(e.Path); err != nil || fi.Size() != e.Size || fi.ModTime().UnixNano() != e.MtimeNano {
				if os.Remove(path) == nil {
					rep.StatRemoved++
				}
			}
		}
	}
	if ents, err := os.ReadDir(s.SpoolDir()); err == nil {
		for _, e := range ents {
			if old(e) && os.Remove(filepath.Join(s.SpoolDir(), e.Name())) == nil {
				rep.SpoolRemoved++
			}
		}
	}
	return rep, nil
}

func removeEmptyDirs(root string) {
	shards, _ := os.ReadDir(root)
	for _, sh := range shards {
		if !sh.IsDir() {
			continue
		}
		shardPath := filepath.Join(root, sh.Name())
		digests, _ := os.ReadDir(shardPath)
		for _, d := range digests {
			_ = os.Remove(filepath.Join(shardPath, d.Name())) // fails when non-empty
		}
		_ = os.Remove(shardPath)
	}
}

// --- atomic writes ---

// Cache files keep mode 0600, which os.CreateTemp gave them before fsx.
const filePerm = 0o600

// WriteImmutable writes path once. An existing entry is left alone, and
// losing a race to another writer is success: entries for the same key
// have the same meaning.
func WriteImmutable(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := fsx.WriteNew(path, data, filePerm); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

// ReplaceFile atomically replaces path's contents.
func ReplaceFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return fsx.WriteFile(path, data, filePerm)
}
