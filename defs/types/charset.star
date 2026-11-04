"""Character-set encodings of text."""

type("charset", parents = ["bytes"], abstract = True, description = "Character-set encodings of text")

type("charset.utf16be", parents = ["charset"], mime = "text/plain; charset=utf-16be", ext = ["txt"], description = "UTF-16 big-endian text")
type("charset.utf16le", parents = ["charset"], mime = "text/plain; charset=utf-16le", ext = ["txt"], description = "UTF-16 little-endian text")
type("charset.utf32le", parents = ["charset"], mime = "text/plain; charset=utf-32le", ext = ["txt"], description = "UTF-32 little-endian text")
type("charset.utf8-bom", parents = ["charset"], mime = "text/plain", description = "UTF-8 with a byte-order mark")
