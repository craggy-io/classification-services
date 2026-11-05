# Samples

Small example files for trying the engine and the CLI. Every file is
synthetic and harmless: the "malicious" ones only have the shape that
triggers an anomaly. They were generated with `internal/testkit`, and
`integration/samples_test.go` checks that each still classifies as listed
here.

```sh
go run ./cmd/craggy-classify --tree samples
go run ./cmd/craggy-classify --fail-on critical samples   # exits 2
go run ./cmd/craggy-classify --depth deep --tree samples/encoded.b64
```

| File | Primary type | Shows |
| --- | --- | --- |
| `app.apk` | `android.apk` | Manifest metadata, a v2 signing block, and children: binary XML, DEX, a native ELF library, JSON |
| `debug.apk` | `android.apk` | `android.debuggable`, `android.unsigned` |
| `slip.zip` | `archive.zip` | `zip.path-traversal` (critical) |
| `elf-with-zip` | `executable.elf` | `polyglot`, `executable.overlay`, `zip.prepended-data`; the hidden script is classified |
| `invoice.pdf` | `executable.pe` | `extension-mismatch` (critical): an executable named as a PDF |
| `form.pdf` | `document.pdf` | `pdf.auto-action`, `pdf.javascript` |
| `report.docm` | `document.docx` | `document.macros` (OOXML) |
| `legacy.xls` | `document.xls` | `document.macros` (OLE2) |
| `plugin.dll` | `executable.dotnet` | DLL and .NET assembly |
| `logs.tar.gz` | `compression.gzip` | Nested derivation: gzip, then tar, then a log and a pcap |
| `capture.pcap` | `network.pcap` | Packet capture with link type and packet count |
| `module.wasm` | `executable.wasm` | Validated by a built-in Starlark classifier |
| `token.jwt` | `crypto.jwt` | `crypto.jwt-unsigned` |
| `encoded.b64` | `encoding.base64` | At `--depth deep`, the decoded JSON is derived and classified |
| `config.json` | `data.json` | |
| `run.sh` | `source.python` | Interpreter from the shebang line, not the extension |
| `notes.txt` | `text` | |
| `current.wdg`, `legacy.wdg` | `text` | Unknown format until the `widgets` bundle is installed |
| `widgets/` | | Example definitions bundle: `bundle.yaml` and the module `acme` (`acme.star`) with inline tests ([guide](../docs/definitions.md#bundles)) |

Try the definition lifecycle on the `.wdg` files:

```sh
go run ./cmd/craggy-classify check samples/widgets          # run its tests (or samples/widgets#acme)
go run ./cmd/craggy-classify preview samples/widgets        # current.wdg, legacy.wdg would change
go run ./cmd/craggy-classify define samples/widgets         # install it
go run ./cmd/craggy-classify samples/legacy.wdg             # acme.widget + acme.legacy warning
go run ./cmd/craggy-classify remove acme
```

Without `--workdir`, the CLI uses `<user cache dir>/craggy/classification`.
