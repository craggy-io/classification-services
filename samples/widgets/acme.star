"""Acme widgets: text starting with WIDGET:."""

type("acme", abstract = True)
type("acme.widget", parents = ["acme", "text"], mime = "text/x-acme-widget", ext = ["wdg"])
signature("acme.widget", at(0, b"WIDGET:"), id = "magic")

def _widget(ctx):
    if ctx.prefix(7) != b"WIDGET:":
        return ctx.reject("acme.widget")
    version = ctx.text()[7:].strip()
    if version == "0":
        ctx.anomaly("acme.legacy", severity = "warning", message = "version 0 widgets are unsupported")
    return ctx.match("acme.widget", level = "validated", version = version)

classifier("widget", produces = ["acme.widget"], requires = ["text"], run = _widget)

test("widget", data = "WIDGET: 2\n", expect = ["acme.widget"], primary = "acme.widget")
test("legacy", data = "WIDGET: 0\n", anomalies = ["acme.legacy"])
test("gadget", data = "GADGET: 2\n", absent = ["acme.widget"])
