#!/usr/bin/env python3
"""Package only the single-machine source; exclude old files in reused folders."""
import hashlib
from pathlib import Path
import tarfile
from render_guide import render
ROOT=Path(__file__).resolve().parents[1]
DIST=ROOT/'dist'
FILES=['README.md','install.sh','server/panel.py','server/control.py','server/core.py','server/converter.py','scripts/build-singbox.sh','scripts/singbox-stats.go','scripts/render_guide.py','scripts/reset-admin.py','scripts/package.py','deploy/Caddyfile','deploy/singlite-panel.service','deploy/singlite-node@.service','deploy/singlite-web.service','dist/index.html','dist/app.js','dist/styles.css']
for name in FILES:
    if not (ROOT/name).is_file():raise SystemExit('源码包不完整：'+name)
guide=(ROOT/'README.md').read_text(encoding='utf-8-sig')
for name in ('deploy-guide.md','deploy-guide.txt'):(DIST/name).write_text(guide,encoding='utf-8-sig')
(DIST/'deploy-guide.html').write_text(render(guide),encoding='utf-8-sig')
FILES += ['dist/deploy-guide.md','dist/deploy-guide.txt','dist/deploy-guide.html']
FILES += [str(p.relative_to(ROOT)) for p in sorted((ROOT/'tests').glob('test_*.py'))]
output=DIST/'singlite-panel.tar.gz'
with tarfile.open(output,'w:gz') as archive:
    for name in FILES:
        path=ROOT/name
        if path.is_symlink():raise SystemExit('源码不应包含符号链接：'+name)
        archive.add(path,arcname='singlite-single/'+name,recursive=False)
(output.with_name(output.name+'.sha256')).write_text(hashlib.sha256(output.read_bytes()).hexdigest()+'  '+output.name+'\n')
print(f'Singlite Single: {output} ({output.stat().st_size:,} bytes)')
