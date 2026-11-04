# Recognisers

[Project](../README.md) · [Documentation index](README.md) · [Walkthrough](walkthrough.md)

Packages `probes` (native recognisers) and `views` (the parsers they share).

## Purpose

Validate formats structurally, extract metadata worth having, derive the
content inside, and report anomalies.

## Views

A view parses a whole input from an `io.ReaderAt` and its size, reads a
bounded amount, and uses only the standard library. Views are registered by
name; the engine memoises one parse per node and name, so parallel
classifiers share it, and every registered view is reachable from Starlark as
`ctx.view.<name>()`. Registering a new view with `views.Register` adds it to
both without any engine change.

| View | Parses | Notable fields |
| --- | --- | --- |
| `zip` | Central directory and EOCD layout | entries, prepended and trailing bytes, duplicate names, traversal names, encrypted count |
| `elf` | Header, program and section tables | class, machine, type, interpreter, image end (overlay boundary) |
| `pe` | DOS stub, COFF, optional header, data directories, sections | machine, DLL, PE32+, subsystem, .NET, Authenticode, overlay |
| `macho` | Thin and universal headers | CPU, file type, slices; rejects Java class files sharing `0xcafebabe` |
| `dex` | DEX header | version and section counts |
| `axml` | Android binary XML | elements and attributes; `Manifest()` gives package, versions, SDKs, permissions, debuggable, exported components |
| `apk-signing-block` | APK Signing Block before the central directory | v2, v3, v3.1 and source-stamp schemes |
| `cfb` | Compound File Binary directory | stream names, application kind, VBA macros |
| `pcap` | pcap and pcapng headers | link type, snap length, packet count (bounded) |
| `ar` | Unix ar members | member names and ranges; Debian packages |

## Built-in probes

Each probe declares what it produces and requires (`probes.Builtins()`); the
engine schedules them like any classifier. Probes change only with
`probes.Revision`.

| Family | Probes | Produces / derives |
| --- | --- | --- |
| Text | `text`, `charset`, `shebang`, `java-source` | `text`; UTF-8 BOM and UTF-16/32 (with and without BOM), deriving the UTF-8 transcoding; scripts by interpreter; Java source |
| Data | `json`, `xml`, `sqlite` | `data.json`, `data.xml` (+ `image.svg`, `data.plist-xml`), `data.sqlite` |
| Encodings | `base64`, `hex`, `digest`, and the `-decode` derivers | `encoding.base64`, `encoding.hex`, `crypto.digest` (with an algorithm guess); speculative decodings at `Deep` |
| Archives | `zip`, `zip-entries`, `tar`, `tar-entries`, `ar`, `cpio`, `rpm` | entries as children (stored ZIP entries and tar/ar members as zero-copy ranges); prepended ZIP data as a child |
| Compression | `gzip`, `bzip2`, `zlib`, `xz`, `zstd` | payloads as children for gzip, bzip2 and zlib (the standard library has no xz or zstd decoder: headers are validated, payloads not derived) |
| Android | `apk`, `dex`, `axml` | APK/APK set/AAB with manifest metadata and signature schemes; DEX; binary XML |
| Executables | `elf`, `pe`, `macho`, `java-class` | ELF and shared objects, PE/DLL/.NET, DOS MZ, Mach-O thin/universal, Java classes; overlays as children |
| Documents | `pdf`, `office-zip`, `cfb` | PDF; OOXML (docx/xlsx/pptx), OpenDocument, EPUB; OLE2 doc/xls/ppt, MSI, Outlook msg |
| Other | `png`, `pcap`, `pem`, `der-certificate`, `jwt` | PNG (IHDR CRC), pcap/pcapng, PEM blocks (derived), X.509 with subject/issuer/validity, JWTs |

Built-in Starlark classifiers live in `defs/classifiers/`: `jar`, `war`,
`ear`, `crx` (deriving the embedded ZIP with `derive_range`) and `wasm`. Each
carries inline tests.

## Anomalies

Anomalies never change which types hold. Codes are stable; switch on `Code`,
not `Message`.

| Code | Severity | Raised when |
| --- | --- | --- |
| `polyglot` | warning | The content validates as unrelated formats (no shared ancestor except `bytes`/`text`). |
| `extension-mismatch` | warning, critical for an executable named as a non-executable | The name's extension is claimed only by types unrelated to any concrete match. |
| `zip.path-traversal` | critical | Entry names are absolute or contain `..` (ZIP slip). |
| `tar.path-traversal` | critical | The same for tar members. |
| `zip.prepended-data` | warning | Data precedes the archive (derived as a child). |
| `zip.trailing-data` | info | Data follows the EOCD record. |
| `zip.duplicate-entry` | warning | A name appears more than once. |
| `zip.encrypted` | info | Entries are encrypted. |
| `zip.expansion-ratio` | warning | An entry declares a ratio above `MaxExpansion` and is not extracted. |
| `zip.entry-too-large` | info | An entry exceeds `MaxDerivedBytes` and is not extracted. |
| `compression.expansion-limit` | warning | A gzip, bzip2 or zlib payload exceeds the expansion limit. |
| `executable.overlay` | info, warning if the overlay starts with a ZIP, PE or ELF magic | Data follows the ELF or PE image (derived as a child). |
| `android.debuggable` | warning | `android:debuggable="true"`. |
| `android.unsigned` | warning | No v1 signature files and no APK Signing Block. |
| `android.v1-signature-only` | info | Signed only with the JAR scheme. |
| `android.manifest-unparsed` | info | `AndroidManifest.xml` is not valid binary XML. |
| `document.macros` | warning | An OOXML `vbaProject.bin` or OLE2 VBA storage is present. |
| `pdf.javascript`, `pdf.auto-action`, `pdf.embedded-file` | warning | `/JavaScript` or `/JS`; `/OpenAction` or `/AA`; `/EmbeddedFile`. |
| `pdf.launch`, `pdf.obfuscated-name` | critical | `/Launch`; security-relevant names hidden with `#xx` escapes. |
| `pdf.leading-data` | warning | Data precedes `%PDF-`. |
| `pdf.encrypted`, `pdf.xfa` | info | `/Encrypt`; `/XFA`. |
| `crypto.private-key` | warning | PEM private-key material. |
| `crypto.jwt-unsigned` | warning | A JWT with `"alg": "none"` or an empty signature. |

Definitions add their own codes with `ctx.anomaly`.
