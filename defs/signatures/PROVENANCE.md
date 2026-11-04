# Signature provenance

`cyberchef.json` is the [CyberChef](https://github.com/gchq/CyberChef)
FileSignatures set (Apache-2.0; see `LICENSE`), originally imported into
computational-research and carried over through cclab-classify. The
`source` and `source_revision` fields record its origin. The rule count
(141) is unchanged.

For classification-services each rule's `type` was retargeted from the old
catalogue ids to this module's `namespace.name` ids (see
[docs/migration.md](../../docs/migration.md)), and each rule `id` was
re-prefixed with its new type. Byte conditions keep their original
predicates (`equal`, `one_of`, `not_equal`, `range`). Signature matches only
produce `candidate` evidence; structural validators raise or refute them.

`extra.star` adds signatures for formats the CyberChef set lacks; they are
original to this module.
