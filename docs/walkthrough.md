# Walkthrough

[Project](../README.md) · [Documentation index](README.md)

This walkthrough classifies some files, explains a result, then writes, checks,
previews and installs a definition. It uses the CLI; every step has a direct
Go equivalent, noted alongside. The outputs below are from a real run. To
follow along, use the files in [`samples/`](../samples/README.md): `slip.zip`,
`current.wdg`, `legacy.wdg` and the definitions bundle `widgets/` (written
as `acme/` below; its module is called `acme`). The
same flows are exercised by `ExampleEngine_Classify`, the `classify` tests and
the CLI test.

## 1. Classify

```sh
$ craggy-classify --workdir /tmp/wd .
a.wdg: text (validated)
acme.star: text (validated)
b.txt: text (validated)
old.wdg: text (validated)
```

(`Engine.ClassifyDir`.) The `.wdg` files are just text: nothing knows the
format yet. Classification hashed each file, read the signature prefix once,
ran every classifier whose requirements held, merged the assertions and
cached the outcome per classifier in the workdir.

## 2. Explain

For any type, `--explain` (`Result.Explain`) shows the evidence or the
rejection:

```sh
$ craggy-classify --explain archive.zip slip.zip
slip.zip: archive.zip (validated)
  ! critical zip.path-traversal: entry names are absolute or escape the extraction directory
  2 derived children (--tree to list)
  archive.zip holds (validated, direct), primary
    validated: asserted by classifier zip
    candidate: signature cyberchef:archive.zip.c95493e2e17e matched 4 bytes at offset 0
```

## 3. Write a definition

`acme/acme.star` is the module from [Definitions](definitions.md): a type, a
signature, a classifier that validates the header and reports an anomaly for
version 0, and three inline tests. The CLI only takes bundles, so it sits in a
folder with a `bundle.yaml` that names the module:

```yaml
apiVersion: craggy.io/bundle/v1
metadata: {id: acme.widgets, version: 1.0.0}
contributions:
  - {id: acme, kind: classify.module@1, path: acme.star}
```

The module's name is the contribution `id`, `acme`, not the file name.

## 4. Check

```sh
$ craggy-classify check acme
acme: adds 2 types, 1 classifiers, 1 signatures
  ok   widget (primary acme.widget)
  ok   legacy (primary acme.widget)
  ok   gadget (primary text)
```

(`Engine.Check`; the CLI loads the bundle with `bundle.Load` and calls
`Engine.CheckModules` with every module in it, or just `acme#acme`'s.) The module compiled, its types fit the catalogue, and the
tests passed against the snapshot that installing it would produce. Nothing
was installed.

## 5. Preview

```sh
$ craggy-classify preview acme
...
examined 4 files, 2 would change
  /tmp/wt/a.wdg: text -> acme.widget  +acme +acme.widget
  /tmp/wt/old.wdg: text -> acme.widget  +acme +acme.widget  anomalies +acme.legacy
```

(`Engine.Preview`.) With no paths given, Preview re-examines files the engine
has classified before that are unchanged on disk, under both snapshots, and
reports the differences. Agents use this to see the blast radius of a
definition before installing it.

## 6. Define, and classify again

```sh
$ craggy-classify define acme
$ craggy-classify --explain acme.widget old.wdg
old.wdg: acme.widget (validated)
  also: text
  ! warning acme.legacy: version 0 widgets are unsupported
  acme.widget holds (validated, direct), primary
    validated: asserted by classifier widget
    candidate: signature acme:magic matched 7 bytes at offset 0
```

(`Engine.Define`.) The module is added to the workdir's installed bundle as
`/tmp/wd/definitions/classify.installed/acme.star`, with its entry written
into that bundle's `bundle.yaml`, and swapped in atomically. On the second classification only the new
`widget` classifier ran: every other classifier's output for these files
came from the cache. Another process using the same workdir sees the module
after `Refresh` (or automatically with `WithAutoRefresh`), and
`craggy-classify remove acme` uninstalls it.

## 7. Into artifact-services

With the [adapter](artifact-services.md), the same classification runs over
an artifact snapshot, and the results become a report artifact, two
validated tables queryable with `sql-v1`, and a lineage activity linking them
to the input.
