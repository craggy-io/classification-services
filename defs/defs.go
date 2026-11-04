// Package defs embeds the built-in definitions: the type catalogue
// (types/), Starlark classifiers (classifiers/) and signatures
// (signatures/, including the imported CyberChef set).
package defs

import (
	"embed"
	"io/fs"
)

//go:embed types classifiers signatures
var files embed.FS

// FS returns the built-in definitions. Every *.star file is a module.
func FS() fs.FS { return files }

// CyberChef returns the imported CyberChef signature set (JSON).
func CyberChef() []byte {
	b, err := files.ReadFile("signatures/cyberchef.json")
	if err != nil {
		panic("defs: missing embedded signatures/cyberchef.json: " + err.Error())
	}
	return b
}
