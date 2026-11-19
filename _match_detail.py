# -*- coding: utf-8 -*-
"""Dump distinct sensitive-value matches per pattern, plus per-file value lists."""
import re, os, io, collections

root = r'D:\ddd'
pats = collections.OrderedDict([
    ('package',   re.compile(r'com\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+')),
    ('winpath',   re.compile(r'[A-Za-z]:\\[^\s"\'|<>]*')),
    ('ipv4',      re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    ('url',       re.compile(r'https?://[^\s"\'<>)]+')),
    ('sha256',    re.compile(r'\b[a-fA-F0-9]{64}\b')),
    ('md5',       re.compile(r'\b[a-fA-F0-9]{32}\b')),
    ('email',     re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')),
    ('androidid', re.compile(r'\b[a-fA-F0-9]{16}\b')),
])

targets = []
for name in ('evidence', 'sandbox', 'tests'):
    base = os.path.join(root, name)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d != '__pycache__']
        for fn in filenames:
            targets.append(os.path.join(dirpath, fn))
for fn in sorted(os.listdir(root)):
    p = os.path.join(root, fn)
    if os.path.isfile(p) and fn.lower().endswith('.md') and not fn.startswith('_'):
        targets.append(p)

TEXT_EXT = {'.md', '.py', '.js', '.txt', '.json', '.yml', '.yaml', '.sh', '.ps1', '.csv', '.toml', '.cfg', '.ini'}
out = io.StringIO()

out.write('FILE INVENTORY (%d files under evidence/sandbox/tests + root md)\n' % len(targets))
out.write('=' * 100 + '\n')
for p in targets:
    ext = os.path.splitext(p)[1].lower()
    sz = os.path.getsize(p)
    out.write('  %-9s %8d  %s\n' % (ext or '(none)', sz, os.path.relpath(p, root)))

out.write('\n' + '=' * 100 + '\n### DISTINCT VALUES PER PATTERN\n')
counter = {k: collections.Counter() for k in pats}
filemap = {k: collections.defaultdict(set) for k in pats}
for p in targets:
    ext = os.path.splitext(p)[1].lower()
    if ext not in TEXT_EXT:
        continue
    try:
        text = open(p, 'r', encoding='utf-8', errors='replace').read()
    except Exception as e:
        out.write('READ FAIL %s: %s\n' % (p, e))
        continue
    for k, rx in pats.items():
        for m in rx.finditer(text):
            v = m.group(0)
            counter[k][v] += 1
            filemap[k][v].add(os.path.relpath(p, root))

for k in pats:
    out.write('\n### %s  unique=%d total=%d\n' % (k, len(counter[k]), sum(counter[k].values())))
    for v, c in counter[k].most_common():
        files = sorted(filemap[k][v])
        out.write('  %4d  %-70s  <- %s\n' % (c, v[:70], ', '.join(files)))

io.open(os.path.join(root, '_match_detail.txt'), 'w', encoding='utf-8', newline='\n').write(out.getvalue())
print('OK', len(targets))
