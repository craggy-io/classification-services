"""Single-stream compression formats."""

type("compression", parents = ["bytes"], abstract = True, description = "Single-stream compression formats")

type("compression.bzip2", parents = ["compression"], mime = "application/x-bzip2", ext = ["bz2"], description = "bzip2 stream")
type("compression.gzip", parents = ["compression"], mime = "application/gzip", ext = ["gz"], description = "gzip stream")
type("compression.lzop", parents = ["compression"], mime = "application/x-lzop", ext = ["lzo", "lzop"], description = "lzop stream")
type("compression.unix-compress", parents = ["compression"], mime = "application/x-compress", ext = ["z", "taz"], description = "Unix compress (.Z, LZW)")
type("compression.xz", parents = ["compression"], mime = "application/x-xz", ext = ["xz"], description = "xz stream")
type("compression.zlib", parents = ["compression"], mime = "application/x-deflate", ext = ["zlib"], description = "zlib stream")
type("compression.zstd", parents = ["compression"], mime = "application/zstd", ext = ["zst"], description = "Zstandard frame")
