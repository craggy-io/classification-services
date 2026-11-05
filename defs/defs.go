// Package defs embeds the built-in definitions as one bundle, ID
// "classify.builtin": the type catalogue (types/), Starlark classifiers
// (classifiers/) and signatures (signatures/, including the imported
// CyberChef set). bundle.yaml lists every module and the CyberChef set; a
// .star file it does not list is not loaded.
package defs

import (
	"embed"
	"io/fs"
)

// ID is the built-in bundle's metadata.id, as written in bundle.yaml.
const ID = "classify.builtin"

//go:embed bundle.yaml types classifiers signatures
var files embed.FS

// FS returns the built-in bundle's files, with bundle.yaml at the root.
func FS() fs.FS { return files }
