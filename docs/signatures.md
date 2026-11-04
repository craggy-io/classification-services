# Signatures

[Project](../README.md) · [Documentation index](README.md) · [Walkthrough](walkthrough.md)

Package `signatures` is the compiled byte-signature matcher.

## Purpose

Produce cheap, fixed-offset `candidate` evidence for every input, so that
`WithDepth(Quick)` is useful on its own and validators have candidates to
confirm or refute.

## Mental model

A rule is a set of patterns at fixed offsets; all must match. Each pattern
position is a 256-bit byte set, so literal bytes, `??` wildcards and the
CyberChef predicates (`equal`, `one_of`, `not_equal`, `range`) are all the
same thing. Rules are bucketed by (offset, first concrete byte). Matching
reads the longest prefix any rule needs once, then checks only the buckets
whose key byte is present.

Each hit records its rule ID, offset and length. These appear as `Evidence`
on the match and in `Explain`.

## Sources of rules

- `defs/signatures/cyberchef.json`: the CyberChef FileSignatures set (Apache-2.0, see `LICENSE` and `PROVENANCE.md` there), 141 rules with types retargeted to this catalogue. Rule IDs are `cyberchef:<type>.<hash>`, with `#n` for each alternative.
- `defs/signatures/extra.star`: rules for formats CyberChef lacks (pcap, pcapng, ar, cpio, rpm, zstd, compound files, Android binary XML, DEX, PEM, Mach-O magics).
- Any module's `signature(...)` declarations: IDs are `<module>:<id>`.

## Levels

Rules default to `candidate`. A module may declare `level = "recognised"` or
`"validated"` for a magic that is decisive on its own, but structural
validation is preferred: a classifier that walks the format can both raise
the level and reject false positives.

## Public interface

`Hex(offset, "50 4b ?? 04")`, `Literal(offset, bytes)`, `Rule`, `New(rules)`
→ `*Matcher` with `Match(prefix, size) []Hit` and `MaxEnd()`, and
`ParseCyberChef(data, module)`.
