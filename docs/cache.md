# Cache

[Project](../README.md) · [Documentation index](README.md) · [Walkthrough](walkthrough.md)

Packages `internal/cache` (the workdir) and `internal/paged` (per-input
reads). Neither is public; this guide describes their behaviour through the
engine.

## Purpose

Never classify the same content with the same classifier twice, across calls,
engines and processes.

## Workdir layout

```
<workdir>/
  definitions/<name>.star          runtime-defined modules (Define / Remove)
  cache/stat/                      (absolute path, size, mtime) -> digest
  cache/results/<ab>/<digest>/
    <classifier>@c1-<rev>.json     one classifier's output for that content
    node@c1-<snapshot>-<depth>-<text>.json   a whole result DAG
  cache/compiled/<srchash>.bin     compiled Starlark programs
  spool/                           large derived children during a call
```

## Keys

- A **classifier entry** is keyed by content digest and the classifier's revision: its identity (module source hash, or native `Spec.Revision`) plus the revisions of every type it produces or requires. It stores assertions, anomalies and child descriptors (name, digest, size), never child bytes, and is written for negative results too.
- A **whole-result entry** is keyed by digest, snapshot revision, depth and the text hint. It stores the node's DAG as a flat table of nodes, so shared children are stored once. It is written only when every node in the subtree is complete, and is used only when no `Recurse` filter is set.
- The **stat index** lets `File` sources skip rehashing unchanged files and lets `Preview` find known files.
- An in-memory LRU (256 entries) holds recent whole results.

After `Define`, whole-result entries miss (the snapshot changed) but
classifier entries hit, so only new or changed classifiers run. When a cached
child's bytes are needed again, its deriver is rerun on the parent.

The `c1` codec version is part of every entry name; changing the encoding
bumps it, so old entries are ignored and later removed by `Maintain`.

## Concurrency

Every entry is written to a temporary file and renamed into place, and is
immutable once written. Two processes sharing a workdir can at worst
duplicate work. There is no lock file and no database. Within a process,
concurrent runs of the same classifier on the same content share one
execution. Definitions are replaced atomically; another engine sees them
after `Refresh` (or automatically with `WithAutoRefresh`).

Failed, cancelled, step-limited and budget-limited runs are not cached.

## Reads

Each content node gets a paged reader: 64 KiB pages, a page cache and a read
budget (`Limits.MaxBytes`) shared by the node's classifiers. Views and JSON
decodes are memoised per node, and a panicking view parser becomes an error.

## Maintenance

`Engine.Maintain(ctx)` (CLI: `craggy-classify maintain`) removes:

- result entries that no classifier or snapshot in the current engine can produce;
- compiled programs for modules no longer loaded;
- stat entries for files that changed or vanished;
- spool and temporary files older than an hour.

It never touches `definitions/` and is safe while other processes use the
workdir: at worst they recompute an entry. An engine configured with extra
native classifiers keeps their entries; another process with a different
configuration may remove them, which costs only recomputation.
