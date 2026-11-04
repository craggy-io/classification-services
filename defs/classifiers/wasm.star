"""WebAssembly binary modules."""

def _wasm(ctx):
    if ctx.prefix(4) != b"\x00asm":
        return None
    if ctx.size < 8:
        return ctx.reject("executable.wasm")
    version = ctx.u32le(4)
    if version != 1:
        return ctx.reject("executable.wasm")
    return ctx.match("executable.wasm", level = "validated", version = version)

classifier("wasm", produces = ["executable.wasm"], run = _wasm)

test("empty module", hex = "0061736d01000000", expect = ["executable.wasm"], primary = "executable.wasm")
test("bad version", hex = "0061736d02000000", absent = ["executable.wasm"])
