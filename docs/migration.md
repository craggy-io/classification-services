# Migration from cclab-classify

[Project](../README.md) · [Documentation index](README.md) · [Walkthrough](walkthrough.md)

classification-services is a clean-break reimplementation of
`github.com/philcantcode/cclab-classify`. The engine design (type DAG,
evidence levels, requires/produces gating, per-classifier cache, content DAG)
carries over; the module path, package layout, type IDs and parts of the API
do not.

## Module and layout

| cclab-classify | classification-services |
| --- | --- |
| `github.com/philcantcode/cclab-classify/src` (one package) | `github.com/craggy-io/classification-services/classify` plus `catalog`, `signatures`, `definitions`, `probes`, `views`, `evidence` |
| `src/probes` with hard-coded `Zip()/Elf()/Dex()` | `probes` + `views` registry; `Input.View(name)` and `classify.View[T]` |
| `src/defs/catalogue.star` | `defs/types/<namespace>.star` |

## API changes

| Before | After |
| --- | --- |
| `Depth(classify.Quick)`, depth values sharing `Level` (101–103) | `WithDepth(classify.Quick)`; `classify.Depth` is its own type |
| `classify.Recognized` alias, `ParseLevel` accepting depths | Removed; `evidence.ParseLevel` still accepts both spellings on input |
| `TypeInfo.Mime`, `TypeInfo.Extensions` aliases | `TypeInfo.MIME`, `TypeInfo.Ext` only; new `Abstract` |
| `Limits.MaxSteps` alias | `Limits.ScriptSteps` |
| `Classifier.Classify` returning `[]Assertion` (children inside) | returns `Output{Assertions, Derived, Anomalies}` |
| `RejectAssertion` | `Refute` |
| `Define(ctx, name, src) error` | `Define(ctx, name, src) (*CheckReport, error)`; inline tests must pass |
| `Open(ctx, "")` used a temporary workdir | a workdir is required |
| cache GC on every `Open` | explicit `Maintain` |
| — | `Check`, `Preview`, `Refresh`, `Test`, `ClassifyMany`, `ClassifyDir`, `Result.Explain`, anomalies, observers, `Source.Named`, the CLI |

Starlark modules keep their shape. Changes: `classifier()` takes `run=` by
keyword (or second positional), `requires` defaults to `["bytes"]`,
`signature()` accepts `id=`, `type()` accepts `abstract=` and no longer
`extensions=`/`doc=`, and `test()`, `ctx.anomaly`, `ctx.name`, `hex` and the
generic `ctx.view.<name>()` are new.

## Type IDs

The old IDs mixed `images.*` with `image.*`, `media.*` with `audio.*` and
`video.*`, and kept a `miscellaneous.*` bucket, `basic.file` above `bytes`,
and 36 shorthand aliases (`json`, `pdf`, `image.png`...) as extra parents.
The new catalogue uses short `namespace.name` IDs under 17 abstract
namespaces (see [catalog](catalog.md)). Aliases are gone: inheritance through
the namespace replaces them.

Every old ID is listed below. CyberChef rules were retargeted with the same
table.

| Old ID | New ID | Note |
| --- | --- | --- |
| `android.aab` | `android.aab` |  |
| `android.apk` | `android.apk` |  |
| `android.apk-bundle` | `android.apk-set` |  |
| `android.dex` | — | v1 shorthand alias; use the canonical type |
| `applications.adobe-flash` | `executable.swf` |  |
| `applications.google-chrome-extension` | `archive.crx` |  |
| `applications.macos-mach-o-64-bit-object` | `executable.macho` |  |
| `applications.macos-mach-o-object` | `executable.macho-universal` |  |
| `applications.windows-portable-executable` | `executable.pe` |  |
| `archive.7z` | — | v1 shorthand alias; use the canonical type |
| `archive.7zip` | `archive.7z` |  |
| `archive.alzip-archive` | `archive.alz` |  |
| `archive.apple-disk-image` | `disk.dmg` | merged with `archive.macintosh-disk-image` |
| `archive.arj-archive` | `archive.arj` |  |
| `archive.bzip2` | `compression.bzip2` |  |
| `archive.container` | `archive` |  |
| `archive.ear` | `archive.ear` |  |
| `archive.gzip` | `compression.gzip` |  |
| `archive.iso-disk-image` | `disk.iso` |  |
| `archive.jar` | — | v1 shorthand alias; use the canonical type |
| `archive.jar-archive` | `archive.jar` |  |
| `archive.kgb-compressed-archive` | `archive.kgb` |  |
| `archive.linux-deb-package` | `archive.deb` |  |
| `archive.lzop-compressed` | `compression.lzop` |  |
| `archive.macintosh-binhex-encoded-file` | `encoding.binhex` |  |
| `archive.macintosh-disk-image` | `disk.dmg` | merged with `archive.apple-disk-image` |
| `archive.microsoft-cabinet` | `archive.cab` |  |
| `archive.rar` | — | v1 shorthand alias; use the canonical type |
| `archive.roshal-archive` | `archive.rar` |  |
| `archive.tar` | — | v1 shorthand alias; use the canonical type |
| `archive.tar-archive` | `archive.tar` |  |
| `archive.tarball` | `compression.unix-compress` |  |
| `archive.virtual-hard-drive` | `disk.vhd` |  |
| `archive.virtual-machine-disk` | `disk.vmdk` |  |
| `archive.war` | `archive.war` |  |
| `archive.winace-archive` | `archive.ace` |  |
| `archive.xz` | — | v1 shorthand alias; use the canonical type |
| `archive.xz-compression` | `compression.xz` |  |
| `archive.zip` | `archive.zip` |  |
| `archive.zlib-deflate` | `compression.zlib` |  |
| `archive.zstd` | `compression.zstd` |  |
| `audio.adaptive-multi-rate-audio-codec` | `audio.amr` |  |
| `audio.audacity` | `audio.au` |  |
| `audio.audacity-block` | `audio.audacity-block` |  |
| `audio.audio-interchange-file` | `audio.aiff` |  |
| `audio.audio-interchange-file-compressed` | `audio.aifc` |  |
| `audio.flac` | — | v1 shorthand alias; use the canonical type |
| `audio.free-lossless-audio-codec` | `audio.flac` |  |
| `audio.mp3` | — | v1 shorthand alias; use the canonical type |
| `audio.mpeg-3-audio` | `audio.mp3` |  |
| `audio.mpeg-4-part-14-audio` | `audio.m4a` |  |
| `audio.musical-instrument-digital-interface-audio` | `audio.midi` |  |
| `audio.ogg` | — | v1 shorthand alias; use the canonical type |
| `audio.ogg-audio` | `audio.ogg` |  |
| `audio.wav` | — | v1 shorthand alias; use the canonical type |
| `audio.waveform-audio` | `audio.wav` |  |
| `basic.file` | `bytes` |  |
| `basic.text` | `text` |  |
| `binary` | `None` |  |
| `binary.dex` | `android.dex` |  |
| `binary.elf` | `executable.elf` |  |
| `binary.java-class` | `executable.java-class` |  |
| `binary.macho` | — | v1 shorthand alias; use the canonical type |
| `binary.object` | `executable` |  |
| `binary.pe` | — | v1 shorthand alias; use the canonical type |
| `binary.shared-object` | `executable.elf-shared-object` |  |
| `database.sqlite` | `data.sqlite` | merged with `miscellaneous.sqlite` |
| `dex` | — | v1 shorthand alias; use the canonical type |
| `document.adobe-postscript` | `document.postscript` | merged with `document.postscript` |
| `document.encapsulated-postscript` | `document.eps` |  |
| `document.epub-e-book` | `document.epub` |  |
| `document.file` | `document` |  |
| `document.microsoft-access-2007-database` | `data.accdb` |  |
| `document.microsoft-access-database` | `data.mdb` |  |
| `document.microsoft-exchange-database` | `data.edb` |  |
| `document.microsoft-office-2007-document` | `document.ooxml` |  |
| `document.microsoft-office-document-ole2` | `document.ole2` |  |
| `document.microsoft-onenote-document` | `document.onenote` |  |
| `document.outlook-express-database` | `data.outlook-dbx` |  |
| `document.pdf` | — | v1 shorthand alias; use the canonical type |
| `document.personal-storage-table-outlook` | `data.outlook-pst` |  |
| `document.portable-document-format` | `document.pdf` |  |
| `document.postscript` | `document.postscript` | merged with `document.adobe-postscript` |
| `document.rich-text-format` | `document.rtf` |  |
| `document.wordperfect-document` | `document.wordperfect` |  |
| `elf` | — | v1 shorthand alias; use the canonical type |
| `encoding.base64` | `encoding.base64` |  |
| `encoding.hex` | `encoding.hex` |  |
| `font.otf` | — | v1 shorthand alias; use the canonical type |
| `font.ttf` | — | v1 shorthand alias; use the canonical type |
| `font.woff` | — | v1 shorthand alias; use the canonical type |
| `font.woff2` | — | v1 shorthand alias; use the canonical type |
| `format.json` | `data.json` |  |
| `image.bmp` | — | v1 shorthand alias; use the canonical type |
| `image.gif` | — | v1 shorthand alias; use the canonical type |
| `image.ico` | — | v1 shorthand alias; use the canonical type |
| `image.jpeg` | — | v1 shorthand alias; use the canonical type |
| `image.png` | — | v1 shorthand alias; use the canonical type |
| `image.svg` | `image.svg` |  |
| `image.tiff` | — | v1 shorthand alias; use the canonical type |
| `image.webp` | — | v1 shorthand alias; use the canonical type |
| `images.adobe-bridge-thumbnail-cache` | `image.bridge-cache` |  |
| `images.autocad-drawing` | `document.dwg` |  |
| `images.bitmap-image` | `image.bmp` |  |
| `images.camera-image-file-format` | `image.crw` |  |
| `images.canon-cr2-raw-image` | `image.cr2` |  |
| `images.fujifilm-raw-image` | `image.raf` |  |
| `images.graphics-interchange-format-image` | `image.gif` |  |
| `images.high-efficiency-image-file-format` | `image.heif` |  |
| `images.icon-image` | `image.ico` |  |
| `images.joint-photographic-experts-group-image` | `image.jpeg` |  |
| `images.jpeg-extended-range-image` | `image.jxr` |  |
| `images.microsoft-document-imaging` | `image.mdi` |  |
| `images.minolta-raw-image` | `image.mrw` |  |
| `images.paint-shop-pro-image` | `image.psp` |  |
| `images.photoshop-image` | `image.psd` |  |
| `images.photoshop-large-document` | `image.psb` |  |
| `images.portable-network-graphics-image` | `image.png` |  |
| `images.radiance-high-dynamic-range-image` | `image.hdr` |  |
| `images.sony-arw-image` | `image.arw` |  |
| `images.tagged-image-file-format-image` | `image.tiff` |  |
| `images.targa-image` | `image.tga` |  |
| `images.the-gimp-image` | `image.xcf` |  |
| `images.webp-image` | `image.webp` |  |
| `java.class` | — | v1 shorthand alias; use the canonical type |
| `json` | — | v1 shorthand alias; use the canonical type |
| `media.audio` | `audio` |  |
| `media.image` | `image` |  |
| `media.video` | `video` |  |
| `miscellaneous.bash` | `source.bash` |  |
| `miscellaneous.bitlocker-recovery-key` | `crypto.bitlocker-key` |  |
| `miscellaneous.bittorrent-link` | `data.torrent` |  |
| `miscellaneous.certificate` | `crypto.certificate` |  |
| `miscellaneous.compiled-html` | `document.chm` |  |
| `miscellaneous.cryptocurrency-wallet` | `crypto.wallet` |  |
| `miscellaneous.embedded-opentype-font` | `font.eot` |  |
| `miscellaneous.lua-bytecode` | `executable.lua-bytecode` |  |
| `miscellaneous.macos-x-keychain` | `crypto.keychain` |  |
| `miscellaneous.opentype-font` | `font.otf` |  |
| `miscellaneous.perl` | `source.perl` |  |
| `miscellaneous.pgp-pubring` | `crypto.pgp-pubring` |  |
| `miscellaneous.pgp-safe` | `crypto.pgp-safe` |  |
| `miscellaneous.pgp-secring` | `crypto.pgp-secring` |  |
| `miscellaneous.php` | `source.php` |  |
| `miscellaneous.plist-binary` | `data.bplist` |  |
| `miscellaneous.plist-xml` | `data.plist-xml` |  |
| `miscellaneous.python` | `source.python` |  |
| `miscellaneous.registry-fragment` | `system.registry-hbin` |  |
| `miscellaneous.registry-script` | `system.registry-script` |  |
| `miscellaneous.ruby` | `source.ruby` |  |
| `miscellaneous.shell` | `source.shell` |  |
| `miscellaneous.smile` | `data.smile` |  |
| `miscellaneous.sqlite` | `data.sqlite` | merged with `database.sqlite` |
| `miscellaneous.task-scheduler` | `system.task-job` |  |
| `miscellaneous.tcp-packet` | `network.tcp-packet` |  |
| `miscellaneous.truetype-font` | `font.ttf` |  |
| `miscellaneous.udp-packet` | `network.udp-packet` |  |
| `miscellaneous.utf-16-le-text` | `charset.utf16le` |  |
| `miscellaneous.utf-32-le-text` | `charset.utf32le` |  |
| `miscellaneous.utf-8-text` | `charset.utf8-bom` |  |
| `miscellaneous.web-open-font-format` | `font.woff` |  |
| `miscellaneous.web-open-font-format-2` | `font.woff2` |  |
| `miscellaneous.webassembly-binary` | `executable.wasm` |  |
| `miscellaneous.windows-event-log` | `system.evtx` |  |
| `miscellaneous.windows-pagedump` | `system.minidump` |  |
| `miscellaneous.windows-password` | `system.pwl` |  |
| `miscellaneous.windows-prefetch` | `system.prefetch` | merged with `miscellaneous.windows-prefetch-win-10` |
| `miscellaneous.windows-prefetch-win-10` | `system.prefetch` | merged with `miscellaneous.windows-prefetch` |
| `miscellaneous.windows-shortcut` | `system.lnk` |  |
| `miscellaneous.winnt-registry-hive` | `system.registry-hive` |  |
| `pdf` | — | v1 shorthand alias; use the canonical type |
| `source.code` | `source` |  |
| `source.java` | `source.java` |  |
| `sqlite` | — | v1 shorthand alias; use the canonical type |
| `text.java` | — | v1 shorthand alias; use the canonical type |
| `text.json` | — | v1 shorthand alias; use the canonical type |
| `text.xml` | `data.xml` | merged with `xml` |
| `value.digest` | `crypto.digest` |  |
| `video.audio-video-interleave` | `video.avi` |  |
| `video.avi` | — | v1 shorthand alias; use the canonical type |
| `video.flash-mp4-video` | `video.f4v` |  |
| `video.flash-video` | `video.flv` |  |
| `video.m4v-video` | `video.m4v` |  |
| `video.matroska-multimedia-container` | `video.mkv` |  |
| `video.mkv` | — | v1 shorthand alias; use the canonical type |
| `video.mp4` | — | v1 shorthand alias; use the canonical type |
| `video.mpeg-4-video` | `video.mp4` |  |
| `video.mpeg-video` | `video.mpeg` |  |
| `video.ogg-video` | `video.ogv` |  |
| `video.quicktime-video` | `video.mov` |  |
| `video.webm` | — | v1 shorthand alias; use the canonical type |
| `video.webm-video` | `video.webm` |  |
| `video.windows-media-video` | `video.wmv` |  |
| `xml` | `data.xml` | merged with `text.xml` |

Types with no old counterpart: `android.axml`, `archive.ar`, `archive.cpio`, `archive.rpm`, `charset.utf16be`, `crypto.jwt`, `crypto.pem`, `crypto.private-key`, `crypto.x509`, `data.outlook-msg`, `data.plist`, `document.doc`, `document.docx`, `document.odf`, `document.ppt`, `document.pptx`, `document.xls`, `document.xlsx`, `executable.dos-mz`, `executable.dotnet`, `executable.msi`, `executable.pe-dll`, `network.pcap`, `network.pcapng`, `source.node`.
