# Catalog

[Project](../README.md) · [Documentation index](README.md) · [Walkthrough](walkthrough.md)

Package `catalog` is the classifier's view of the type DAG.

## Purpose

Name every type once, relate types by `parents`, and answer `IsA` in
constant time.

The graph itself (names, parents, `IsA`, ancestors and its validity rules)
is foundation-kit's [`taxonomy`](https://github.com/craggy-io/foundation-kit/blob/main/taxonomy/README.md)
package, which other libraries share. This package adds what only a file
classifier knows about a type: its MIME type, extensions and priority, and
the rules below that are specific to file contents.

## One graph for a whole host

By default an engine keeps a taxonomy of its own. A host that holds a
`taxonomy.Live` passes it to `classify.Open` with `WithTaxonomy(live)`, and
the engine then shares one graph with every other owner:

- The engine declares its types in `live` under the owner
  `classify.TaxonomyOwner`, on `Open` and on every `Define`, `Remove` and
  `Refresh`. `Close` withdraws them, which fails while another owner's types
  still descend from them.
- A definition may give a type a parent that another owner declared. Such a
  type still needs a parent that descends from `bytes` to be asserted about
  content.
- `Types`, `Type` and `IsA` cover the whole graph. Another owner's type has
  no MIME type or extensions.
- Call `Refresh` after another owner changes the taxonomy.
- `Check` and `Preview` validate against `live` without publishing to it.
- Use one engine per live taxonomy, because the owner name is fixed.

## Mental model

Each type declares its parents; ancestor sets are precomputed when the
catalogue is built. A direct `android.apk` match implies `archive.zip`,
`archive`, `android` and `bytes`, and each inherited match records which
direct match it came through. Depth (the longest parent path to `bytes`)
measures specificity.

## Naming rules

- Two roots, declared by the engine: `bytes` (all content) and `text` (UTF-8 text).
- Every other type is `namespace.name`: lower-case letters, digits and `.-_+`.
- A namespace (`archive`) is itself an **abstract** type. When a namespace type exists, every type in it must descend from it, so membership and `IsA` agree. Build fails otherwise.
- Abstract types group others. Classifiers can require them, but they are never the primary type while a concrete descendant holds.
- A type with no `parents` is parented under `bytes`. Every type the engine declares descends from `bytes`; other roots can only come from another owner of a shared taxonomy.
- Identical redeclarations are allowed (two modules may share a type); conflicting ones are errors, as are cycles and unknown parents.

## Built-in catalogue

`defs/types/<namespace>.star`: 187 types in 17 namespaces. List them with
`craggy-classify types` or `Engine.Types()`.

| Namespace | Types | Examples |
| --- | --- | --- |
| `android` | 5 | android.apk android.apk-set android.aab android.dex android.axml |
| `archive` | 17 | archive.zip archive.jar archive.war archive.tar archive.ar archive.deb archive.rpm archive.cpio archive.crx |
| `audio` | 11 | audio.flac audio.mp3 audio.ogg audio.wav |
| `charset` | 4 | charset.utf8-bom charset.utf16le charset.utf16be charset.utf32le |
| `compression` | 7 | compression.gzip compression.bzip2 compression.xz compression.zstd compression.zlib |
| `crypto` | 12 | crypto.x509 crypto.pem crypto.private-key crypto.jwt crypto.digest |
| `data` | 14 | data.json data.xml data.sqlite data.plist-xml data.outlook-pst |
| `disk` | 4 | disk.iso disk.dmg disk.vhd disk.vmdk |
| `document` | 18 | document.pdf document.docx document.xlsx document.pptx document.odf document.ole2 document.doc |
| `encoding` | 3 | encoding.base64 encoding.hex encoding.binhex |
| `executable` | 13 | executable.elf executable.pe executable.pe-dll executable.dotnet executable.macho executable.java-class executable.wasm |
| `font` | 5 | font.ttf font.otf font.woff2 |
| `image` | 23 | image.png image.jpeg image.gif image.svg image.webp |
| `network` | 4 | network.pcap network.pcapng |
| `source` | 8 | source.java source.python source.shell source.bash source.node |
| `system` | 9 | system.evtx system.lnk system.registry-hive system.prefetch |
| `video` | 11 | video.mp4 video.mkv video.webm |

Several types have more than one parent where a format genuinely is two
things: `android.apk` is `archive.zip` and `android`; `data.json` is `data`
and `text`; `executable.msi` is `executable` and `document.ole2`;
`image.svg` is `image` and `data.xml`.

## Revisions

`Catalog.Revision()` identifies the whole catalogue. `TypeRevision(t)`
identifies one type's definition and is part of every classifier's cache
key, so editing a type invalidates the classifiers that read it and nothing
else.

## Public interface

`Build([]TypeInfo) (*Catalog, error)`, `BuildIn(live, owner, []TypeInfo)`,
`Has`, `Get`, `IsA`, `Ancestors`, `Depth`, `Closure`, `ByExtension`, `Types`,
`Len`, `Revision`, `TypeRevision`, `Taxonomy`, `Own`, and `Namespace(name)`.
