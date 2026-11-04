"""Reports SVG text that overflows its enclosing rect or collides with other
text. Monospace advance is taken as 0.6 em (JetBrains Mono, Liberation Mono,
DejaVu Sans Mono) with a 4% margin for bold and hinting."""
import re, sys
ADV = 0.62
def parse(path):
    s = open(path).read()
    rects = [tuple(float(v) for v in m) for m in re.findall(r'<rect x="([\d.]+)" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)"', s)]
    texts = []
    for m in re.finditer(r'<text x="([\d.]+)" y="([\d.]+)" font-size="([\d.]+)"[^>]*text-anchor="(\w+)">([^<]*)</text>', s):
        x, y, size, anchor, t = float(m[1]), float(m[2]), float(m[3]), m[4], m[5]
        t = t.replace('&gt;', '>').replace('&lt;', '<').replace('&amp;', '&')
        w = len(t) * size * ADV
        x0 = {'start': x, 'middle': x - w/2, 'end': x - w}[anchor]
        texts.append((x0, y - size*0.8, x0 + w, y + size*0.2, t))
    return rects, texts
def check(path):
    rects, texts = parse(path)
    bad = 0
    for (x0, y0, x1, y1, t) in texts:
        if not t.strip(): continue
        inside = [r for r in rects if r[0] <= x0+1 and r[1] <= y0 and y1 <= r[1]+r[3] and r[2] < 1400]
        # smallest rect containing the text's start point
        holder = [r for r in rects if r[0] <= x0+1 <= r[0]+r[2] and r[1] <= y0 <= r[1]+r[3] and r[2] < 1400]
        if holder:
            r = min(holder, key=lambda r: r[2]*r[3])
            if x1 > r[0] + r[2] - 12:
                print(f'{path}: overflow by {x1-(r[0]+r[2]-12):.0f}px: {t!r}'); bad += 1
            if y1 > r[1] + r[3] - 12:
                print(f'{path}: too close to the bottom edge by {y1-(r[1]+r[3]-12):.0f}px: {t!r}'); bad += 1
        else:
            for r in rects:
                if r[2] >= 1400: continue
                if x0 < r[0]+r[2] and x1 > r[0] and y0 < r[1]+r[3] and y1 > r[1]:
                    print(f'{path}: label overlaps a box: {t!r}'); bad += 1; break
    for i, a in enumerate(texts):
        for b in texts[i+1:]:
            if a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3] and a[4].strip() and b[4].strip():
                print(f'{path}: text collision: {a[4]!r} / {b[4]!r}'); bad += 1
    return bad
sys.exit(1 if sum(check(p) for p in sys.argv[1:]) else 0)
