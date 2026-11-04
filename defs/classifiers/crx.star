"""Chrome extensions: a CRX header followed by a ZIP, derived as a child."""

def _crx(ctx):
    if ctx.size < 16 or ctx.prefix(4) != b"Cr24":
        return None
    version = ctx.u32le(4)
    if version == 3:
        start = 12 + ctx.u32le(8)
    elif version == 2:
        start = 16 + ctx.u32le(8) + ctx.u32le(12)
    else:
        return ctx.reject("archive.crx")
    if start + 4 > ctx.size or ctx.read(start, 4) != b"PK\x03\x04":
        return ctx.reject("archive.crx")
    ctx.derive_range("extension.zip", start, ctx.size - start)
    return ctx.match("archive.crx", level = "validated", crx_version = version)

classifier("crx", produces = ["archive.crx"], derives = True, run = _crx)

test(
    "crx3 with an embedded zip",
    hex = (
    "437232340300000000000000504b03041400000000000000215c43bfa6a30200" +
    "0000020000000d0000006d616e69666573742e6a736f6e7b7d504b0102140314" +
    "00000000000000215c43bfa6a302000000020000000d00000000000000000000" +
    "008001000000006d616e69666573742e6a736f6e504b05060000000001000100" +
    "3b0000002d0000000000"
    ),
    expect = ["archive.crx"],
    anomalies = ["zip.prepended-data"],
)

test(
    "unknown crx version is rejected",
    hex = "437232340900000000000000504b0304",
    absent = ["archive.crx"],
)

test(
    "no zip at the computed start is rejected",
    hex = "4372323403000000000000005858585858585858",
    absent = ["archive.crx"],
)
