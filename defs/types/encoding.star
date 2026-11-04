"""Text encodings of binary data."""

type("encoding", parents = ["text"], abstract = True, description = "Text encodings of binary data")

type("encoding.base64", parents = ["encoding"], mime = "text/plain", ext = ["b64"], description = "Base64 text")
type("encoding.binhex", parents = ["encoding"], mime = "application/mac-binhex", ext = ["hqx"], description = "BinHex 4.0")
type("encoding.hex", parents = ["encoding"], mime = "text/plain", description = "Hexadecimal text")
