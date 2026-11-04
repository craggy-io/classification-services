"""Java archives: JAR, WAR and EAR are ZIPs distinguished by their entries."""

def _main_class(manifest):
    for line in str(manifest).split("\n"):
        line = line.strip()
        if line.startswith("Main-Class:"):
            return line[len("Main-Class:"):].strip()
    return ""

def _jar(ctx):
    z = ctx.view.zip()
    if not z.has("META-INF/MANIFEST.MF"):
        return ctx.reject("archive.jar")
    mc = _main_class(z.read("META-INF/MANIFEST.MF", limit = 65536))
    if mc:
        return ctx.match("archive.jar", level = "validated", main_class = mc)
    return ctx.match("archive.jar", level = "validated")

def _war(ctx):
    z = ctx.view.zip()
    if z.has("WEB-INF/web.xml") or z.has_prefix("WEB-INF/classes/"):
        return ctx.match("archive.war", level = "validated")
    return ctx.reject("archive.war")

def _ear(ctx):
    z = ctx.view.zip()
    if z.has("META-INF/application.xml"):
        return ctx.match("archive.ear", level = "validated")
    return ctx.reject("archive.ear")

classifier("jar", produces = ["archive.jar"], requires = ["archive.zip"], run = _jar)
classifier("war", produces = ["archive.war"], requires = ["archive.zip"], run = _war)
classifier("ear", produces = ["archive.ear"], requires = ["archive.zip"], run = _ear)

test(
    "jar with a main class",
    hex = (
    "504b03041400000000000000215c19f0a5263300000033000000140000004d45" +
    "54412d494e462f4d414e49464553542e4d464d616e69666573742d5665727369" +
    "6f6e3a20312e300a4d61696e2d436c6173733a20636f6d2e6578616d706c652e" +
    "4d61696e0a504b010214031400000000000000215c19f0a52633000000330000" +
    "001400000000000000000000008001000000004d4554412d494e462f4d414e49" +
    "464553542e4d46504b0506000000000100010042000000650000000000"
    ),
    filename = "app.jar",
    expect = ["archive.jar", "archive.zip"],
    primary = "archive.jar",
)

test(
    "plain zip is not a jar",
    hex = (
    "504b03041400000000000000215c86a61036050000000500000005000000612e" +
    "74787468656c6c6f504b010214031400000000000000215c86a6103605000000" +
    "05000000050000000000000000000000800100000000612e747874504b050600" +
    "0000000100010033000000280000000000"
    ),
    expect = ["archive.zip"],
    absent = ["archive.jar", "archive.war"],
    primary = "archive.zip",
)

test(
    "war",
    hex = (
    "504b03041400000000000000215cd0f276720a0000000a0000000f0000005745" +
    "422d494e462f7765622e786d6c3c7765622d6170702f3e504b01021403140000" +
    "0000000000215cd0f276720a0000000a0000000f000000000000000000000080" +
    "01000000005745422d494e462f7765622e786d6c504b05060000000001000100" +
    "3d000000370000000000"
    ),
    expect = ["archive.war"],
)

test(
    "ear",
    hex = (
    "504b03041400000000000000215cd831cbe70e0000000e000000180000004d45" +
    "54412d494e462f6170706c69636174696f6e2e786d6c3c6170706c6963617469" +
    "6f6e2f3e504b010214031400000000000000215cd831cbe70e0000000e000000" +
    "1800000000000000000000008001000000004d4554412d494e462f6170706c69" +
    "636174696f6e2e786d6c504b0506000000000100010046000000440000000000"
    ),
    expect = ["archive.ear"],
)
