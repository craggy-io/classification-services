// Package views holds the parsed structures shared by classifiers: ZIP
// central directories, executable headers, Android binary XML and so on.
// Every parser takes an io.ReaderAt plus its size, reads a bounded amount and
// depends only on the standard library, so views are testable and reusable
// on their own.
//
// Parsers that apply to a whole input are registered by name. The engine
// memoises one parse per input and name, which is how parallel classifiers
// share a single ZIP central-directory walk, and how a Starlark definition's
// ctx.view.<name>() reaches the same structure a Go probe sees. Registering a
// new view makes it available to both without changing any engine API.
package views

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// Revision identifies the view parser implementations. It feeds
// classifier cache keys (definitions read views), so bump it when a
// parser's behaviour changes.
const Revision = "views-v2"

// Parser parses a whole input into a view value.
type Parser func(ra io.ReaderAt, size int64) (any, error)

// Describer is implemented by views that can present themselves as plain
// data (strings, bools, int64, float64, []any, map[string]any). Starlark
// definitions see a described view as a read-only struct.
type Describer interface {
	Describe() map[string]any
}

var (
	mu       sync.RWMutex
	registry = map[string]Parser{}
)

// Register adds a named whole-input parser. It panics on a duplicate name,
// since registration happens at init time.
func Register(name string, p Parser) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("views: duplicate view %q", name))
	}
	registry[name] = p
}

// Lookup returns the parser for name.
func Lookup(name string) (Parser, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	return p, ok
}

// Names lists registered views, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func init() {
	Register("zip", func(ra io.ReaderAt, size int64) (any, error) { return ParseZip(ra, size) })
	Register("elf", func(ra io.ReaderAt, size int64) (any, error) { return ParseELF(ra, size) })
	Register("dex", func(ra io.ReaderAt, size int64) (any, error) { return ParseDex(ra, size) })
	Register("pe", func(ra io.ReaderAt, size int64) (any, error) { return ParsePE(ra, size) })
	Register("macho", func(ra io.ReaderAt, size int64) (any, error) { return ParseMachO(ra, size) })
	Register("axml", func(ra io.ReaderAt, size int64) (any, error) { return ParseAXMLAt(ra, size) })
	Register("cfb", func(ra io.ReaderAt, size int64) (any, error) { return ParseCFB(ra, size) })
	Register("pcap", func(ra io.ReaderAt, size int64) (any, error) { return ParsePcap(ra, size) })
	Register("ar", func(ra io.ReaderAt, size int64) (any, error) { return ParseAr(ra, size) })
	Register("apk-signing-block", func(ra io.ReaderAt, size int64) (any, error) { return ParseAPKSigningBlock(ra, size) })
}

// ReadRange reads up to n bytes at off, tolerating a short read at EOF.
func ReadRange(ra io.ReaderAt, size, off, n int64) ([]byte, error) {
	if off < 0 || n < 0 {
		return nil, fmt.Errorf("views: negative range (%d, %d)", off, n)
	}
	if off >= size || n == 0 {
		return nil, nil
	}
	n = min(n, size-off)
	buf := make([]byte, n)
	rd, err := ra.ReadAt(buf, off)
	if err == io.EOF {
		err = nil
	}
	return buf[:rd], err
}

// readExact reads exactly n bytes at off or fails.
func readExact(ra io.ReaderAt, size, off, n int64) ([]byte, error) {
	b, err := ReadRange(ra, size, off, n)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != n {
		return nil, fmt.Errorf("views: truncated read at offset %d (want %d bytes, have %d)", off, n, len(b))
	}
	return b, nil
}

func strs(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
