"""Generates the documentation diagrams in this folder and checks that no
text overflows its box. Run: python3 docs/assets/diagrams.py"""
import os
from xml.sax.saxutils import escape as e
HERE = os.path.dirname(os.path.abspath(__file__))
AMB, TXT, BG, CARD, EDGE, RULE, BAND, DASH = '#FFB547', '#E4ECE7', '#111A20', '#16222A', '#4A3F2C', '#2A2F2C', '#2A2F2C', '#B9852F'
FONT = "'JetBrains Mono', Consolas, 'Liberation Mono', monospace"

class SVG:
    def __init__(s, w, h, title, desc):
        s.w, s.h, s.out = w, h, []
        s.out.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-labelledby="title desc">')
        s.out.append(f'<title id="title">{e(title)}</title>\n<desc id="desc">{e(desc)}</desc>')
        s.out.append(f'<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M1 1 L9 5 L1 9" fill="none" stroke="{AMB}" stroke-width="1.5"/></marker></defs>')
        s.out.append(f'<rect width="{w}" height="{h}" rx="20" fill="{BG}"/>\n<g font-family="{FONT}">')
    def text(s, x, y, t, size=20, fill=TXT, bold=False, anchor='start'):
        s.out.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" font-weight="{700 if bold else 400}" text-anchor="{anchor}">{e(t)}</text>')
    def header(s, title, sub, right):
        s.text(40, 53, '> ' + title, 28, AMB, True); s.text(40, 87, sub, 22)
        s.text(s.w-40, 53, right, 18, anchor='end')
        s.out.append(f'<path d="M40 111 H{s.w-40}" fill="none" stroke="{RULE}" stroke-width="2" />')
    def card(s, x, y, w, h, name, lines, size=30):
        s.out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{CARD}" stroke="{EDGE}" stroke-width="1.5"/>')
        s.out.append(f'<path d="M{x+22} {y+22} H{x+56}" fill="none" stroke="{AMB}" stroke-width="3" />')
        s.text(x+22, y+60, name, size, bold=True)
        for i, l in enumerate(lines):
            s.text(x+22, y+96+30*i, l, 19)
    def arrow(s, d, label=None, lx=0, ly=0, head=True):
        m = ' marker-end="url(#arrow)"' if head else ''
        s.out.append(f'<path d="{d}" fill="none" stroke="{AMB}" stroke-width="2"{m}/>')
        if label: s.text(lx, ly, label, 17, AMB, anchor='middle')
    def dash(s, d):
        s.out.append(f'<path d="{d}" fill="none" stroke="{DASH}" stroke-width="1.5" stroke-dasharray="4 6"/>')
    def band(s, x, y, w, h, title, left, right1, right2):
        s.out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{BAND}" stroke="#7A5C30"/>')
        s.text(x+22, y+35, title, 22, AMB, True); s.text(x+22, y+66, left, 18)
        s.text(x+520, y+35, right1, 21); s.text(x+520, y+66, right2, 19)
    def save(s, path):
        s.out.append('</g></svg>')
        open(path, 'w').write('\n'.join(s.out) + '\n')

# --- architecture -------------------------------------------------------------
ADV = 0.62  # monospace advance per em, with margin (see check_svg.py)
def need(title, lines, tsize):
    return int(max(len(title)*tsize*ADV, *(len(l)*19*ADV for l in lines)) + 44)

cols = [
    ('01 / ENGINE', [('Classify', ['Engine / Result DAG', 'Explain / anomalies', 'Check / Define', 'Batch / CLI'], 30, 200)]),
    ('02 / DEFINITIONS', [('Definitions', ['Starlark + test()'], 26, 112), ('Catalog', ['Type DAG / namespaces'], 26, 100), ('Signatures', ['CyberChef + at() rules'], 26, 100)]),
    ('03 / RECOGNISERS', [('Probes', ['Native recognisers', 'Findings + anomalies'], 26, 160), ('Views', ['ZIP ELF PE Mach-O', 'DEX AXML CFB pcap', 'Registered by name'], 26, 172)]),
    ('04 / WORKDIR', [('Cache', ['Classifier outputs', 'Whole-result DAGs', 'Stat index / GC'], 26, 160), ('Paged input', ['64 KiB page cache', 'Read budget', 'Memoised views'], 26, 172)]),
]
widths = [max(need(t, l, ts) for t, l, ts, _ in cards) for _, cards in cols]
gap = (1360 - sum(widths)) // (len(cols) - 1)
assert gap >= 80, f'columns too wide for arrow labels (gap {gap})'
xs, x = [], 40
for w in widths:
    xs.append(x); x += w + gap
a = SVG(1440, 760, 'Classification Services layer architecture',
        'Classify (engine and results) uses Definitions (Starlark modules), the Catalog type DAG and Signatures, runs Probes over shared Views, and caches in the workdir through the paged reader and cache. The evidence vocabulary (levels and anomalies) spans every layer. An optional adapter module connects to artifact-services.')
a.header('CLASSIFICATION SERVICES', 'Every type content can be shown to be', 'LAYER ARCHITECTURE')
box = {}
for (label, cards), cx, w in zip(cols, xs, widths):
    a.text(cx, 145, label, 17, AMB)
    y = 167
    for title, lines, ts, h in cards:
        h = 96 + 30 * (len(lines) - 1) + 24
        a.card(cx, y, w, h, title, lines, ts)
        box[title] = (cx, y, w, h)
        y += h + 20
def right(n): return box[n][0] + box[n][2]
def left(n): return box[n][0]
def mid(a0, b0): return (a0 + b0) // 2
cl, de, pr, vi, pa = box['Classify'], box['Definitions'], box['Probes'], box['Views'], box['Paged input']
# Classify -> Definitions ("loads"), label above the arrow in the gap
ly = de[1] + 56
a.arrow(f'M{right("Classify")} {ly} H{left("Definitions")}', 'loads', mid(right('Classify'), left('Definitions')), ly - 10)
# Classify -> Probes ("runs"): below Definitions, through the gap, up into Probes
gy = de[1] + de[3] + 10
gx = mid(right('Definitions'), left('Probes'))
py = pr[1] + 56
a.arrow(f'M{right("Classify")} {gy} H{gx} V{py} H{left("Probes")}', None)
a.text(gx, py - 10, 'runs', 17, AMB, anchor='middle')
# Probes -> Views
vx = pr[0] + pr[2] // 2
a.arrow(f'M{vx} {pr[1] + pr[3]} V{vi[1]}', None)
# Views -> Paged input ("parses")
vy = vi[1] + 72
a.arrow(f'M{right("Views")} {vy} H{left("Paged input")}', 'parses', mid(right('Views'), left('Paged input')), vy - 10)
# Classify -> workdir ("caches / reads") along the bottom
by = max(b[1] + b[3] for b in box.values()) + 22
px = pa[0] + pa[2] // 2
a.arrow(f'M{right("Classify")} {cl[1] + cl[3] - 30} H{right("Classify") + 25} V{by} H{px} V{pa[1] + pa[3]}', None)
a.text(mid(right('Classify'), px), by - 8, 'caches / reads', 17, AMB, anchor='middle')
band = by + 40
for cx, w in zip(xs, widths):
    a.dash(f'M{cx + w // 2} {by + 12} V{band}')
a.band(40, band, 1360, 84, 'EVIDENCE VOCABULARY', 'Every layer', 'Candidate < Recognised < Validated', 'Anomalies: code / severity / reporter')
a.text(40, band + 108, 'Arrows: dependencies (one way, no cycles)', 16)
a.text(1400, band + 108, 'adapters/artifactsvc: separate module for artifact-services', 16, anchor='end')
a.save(os.path.join(HERE, 'classification-services-architecture.svg'))

# --- pipeline -----------------------------------------------------------------
p = SVG(1440, 560, 'How one input is classified',
        'Roots are asserted, signatures add candidates, the worklist runs classifiers whose required types hold, assertions merge with rejections and inheritance, anomalies are added, and derived children are classified recursively into a content DAG.')
p.header('CLASSIFY', 'One input, start to finish', 'PIPELINE')
steps = [('Roots', ['bytes', '(+ text)']), ('Signatures', ['prefix read', 'candidates']), ('Worklist', ['requires gate', 'parallel runs']),
         ('Merge', ['rejections', 'inheritance']), ('Anomalies', ['polyglot', 'name hint']), ('Derive', ['children by', 'digest (DAG)'])]
x = 40
for i, (n, ls) in enumerate(steps):
    p.card(x, 150, 200, 190, n, ls, 26)
    if i < len(steps)-1:
        p.arrow(f'M{x+200} 245 H{x+232}')
    x += 232
p.arrow('M1272 340 V380 H140 V340', 'each child is classified the same way (cycle, depth, size and ratio limits)', 706, 405)
p.band(40, 440, 1360, 84, 'CACHED PER STEP', 'Workdir', 'Classifier outputs keyed by (digest, classifier@revision)', 'Whole results keyed by (digest, snapshot, depth)')
p.save(os.path.join(HERE, 'classify-pipeline.svg'))
import subprocess, sys
sys.exit(subprocess.call([sys.executable, os.path.join(HERE, 'check_svg.py'), os.path.join(HERE, 'classification-services-architecture.svg'), os.path.join(HERE, 'classify-pipeline.svg')]))
