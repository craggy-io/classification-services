"""Fonts."""

type("font", parents = ["bytes"], abstract = True, description = "Fonts")

type("font.eot", parents = ["font"], mime = "application/octet-stream", ext = ["eot"], description = "Embedded OpenType font")
type("font.otf", parents = ["font"], mime = "application/font-sfnt", ext = ["otf"], description = "OpenType font")
type("font.ttf", parents = ["font"], mime = "application/font-sfnt", ext = ["ttf"], description = "TrueType font")
type("font.woff", parents = ["font"], mime = "application/font-woff", ext = ["woff"], description = "WOFF font")
type("font.woff2", parents = ["font"], mime = "application/font-woff", ext = ["woff2"], description = "WOFF2 font")
