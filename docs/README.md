# Documentation

[Project](../README.md) · [Walkthrough](walkthrough.md)

Each guide describes the available API, its behaviour and limits, and how it
relates to the other layers. Domain operations take a context first.

## Layer guides

- [Classify](classify.md): the engine, sources, results, merging, derivation, anomalies, batch work and observation.
- [Definitions](definitions.md): Starlark modules, the `ctx` API, inline tests, and the check → preview → define lifecycle.
- [Catalog](catalog.md): the type DAG, namespaces and the built-in catalogue.
- [Signatures](signatures.md): byte signatures and the CyberChef import.
- [Recognisers](recognisers.md): built-in probes, shared views, and every anomaly code.
- [Cache](cache.md): the workdir, cache keys, concurrency and maintenance.

## Tools and integration

- [CLI](cli.md): `craggy-classify`.
- [Artifact Services](artifact-services.md): the `adapters/artifactsvc` module.

## Shared guides

- [Walkthrough](walkthrough.md): classify, explain, write and install a definition, preview its impact.
- [Migration](migration.md): from cclab-classify, including the full type-ID table.
- [Verification](verification.md): what is tested and how to run it.

## Branding

The two wordmarks in `assets/` are unchanged copies of the Craggy brand kit
variants also used by artifact-services. The diagrams follow the same palette
(amber `#FFB547` on `#111A20`) and JetBrains Mono.

The diagrams are generated: edit and run `python3 docs/assets/diagrams.py`,
which rewrites both SVGs and fails if any text overflows its box
(`check_svg.py`, assuming 0.6 em monospace glyphs).
