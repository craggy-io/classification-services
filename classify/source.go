package classify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Source is content to classify. Construct one with File, Bytes, Text or
// ReaderAt; Named attaches a file-name hint.
type Source struct {
	kind string // "file", "bytes", "readerat"
	path string
	data []byte
	ra   io.ReaderAt
	size int64
	text bool
	name string
}

// File classifies the file at path. Its base name is the name hint.
func File(path string) Source {
	return Source{kind: "file", path: path, name: filepath.Base(path)}
}

// Bytes classifies an in-memory slice. The slice is not copied and must not
// change during classification.
func Bytes(b []byte) Source {
	return Source{kind: "bytes", data: b, size: int64(len(b))}
}

// Text classifies a string and asserts the "text" root type.
func Text(s string) Source {
	return Source{kind: "bytes", data: []byte(s), size: int64(len(s)), text: true}
}

// ReaderAt classifies content from an io.ReaderAt of known size.
func ReaderAt(r io.ReaderAt, size int64) Source {
	return Source{kind: "readerat", ra: r, size: size}
}

// Named returns a copy of s with a file-name hint. The name never changes
// which types hold; it lets the engine report an "extension-mismatch"
// anomaly when the content disagrees with the extension, and is visible to
// classifiers as ctx.name.
func (s Source) Named(name string) Source {
	s.name = filepath.Base(name)
	return s
}

// content is a materialised, hashed Source.
type content struct {
	ra     io.ReaderAt
	size   int64
	digest string
	text   bool
	name   string
	path   string // absolute path for File sources
	close  func() error
	spool  string // spool file to remove on Close
}

func (c *content) Close() error {
	var err error
	if c.close != nil {
		err = c.close()
		c.close = nil
	}
	if c.spool != "" {
		os.Remove(c.spool)
		c.spool = ""
	}
	return err
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hashReaderAt(ra io.ReaderAt, size int64) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(ra, 0, size)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ErrInvalidSource reports an empty or malformed Source.
var ErrInvalidSource = errors.New("classify: invalid source")

func (e *Engine) materialise(src Source) (*content, error) {
	switch src.kind {
	case "bytes":
		return &content{ra: bytes.NewReader(src.data), size: src.size, digest: sha256Hex(src.data), text: src.text, name: src.name}, nil
	case "readerat":
		if src.ra == nil || src.size < 0 {
			return nil, fmt.Errorf("%w: ReaderAt needs a reader and a non-negative size", ErrInvalidSource)
		}
		d, err := hashReaderAt(src.ra, src.size)
		if err != nil {
			return nil, fmt.Errorf("classify: hashing source: %w", err)
		}
		return &content{ra: src.ra, size: src.size, digest: d, text: src.text, name: src.name}, nil
	case "file":
		if src.path == "" {
			return nil, fmt.Errorf("%w: File needs a path", ErrInvalidSource)
		}
		f, err := os.Open(src.path)
		if err != nil {
			return nil, err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		if !fi.Mode().IsRegular() {
			f.Close()
			return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalidSource, src.path)
		}
		abs, err := filepath.Abs(src.path)
		if err != nil {
			abs = src.path
		}
		digest := e.store.StatLookup(abs, fi)
		if digest == "" {
			if digest, err = hashReaderAt(f, fi.Size()); err != nil {
				f.Close()
				return nil, err
			}
			e.store.StatStore(abs, fi, digest)
		}
		return &content{ra: f, size: fi.Size(), digest: digest, path: abs, name: src.name, close: f.Close}, nil
	}
	return nil, fmt.Errorf("%w: use File, Bytes, Text or ReaderAt", ErrInvalidSource)
}
