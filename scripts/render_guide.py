"""Render the distribution's small Markdown subset without external dependencies."""
import html
import re


def inline(value):
    value = html.escape(value)
    value = re.sub(r'`([^`]+)`', r'<code>\1</code>', value)
    value = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', value)
    return re.sub(r'\[([^\]]+)\]\((https?://[^\s)]+)\)', r'<a href="\2">\1</a>', value)


def render(markdown):
    lines = markdown.lstrip('\ufeff').splitlines()
    blocks, headings = [], []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith('```'):
            code = []
            i += 1
            while i < len(lines) and not lines[i].startswith('```'):
                code.append(lines[i])
                i += 1
            blocks.append('<pre><code>' + html.escape('\n'.join(code)) + '</code></pre>')
            i += 1
            continue
        heading = re.match(r'^(#{1,3}) (.+)$', line)
        if heading:
            level, title = len(heading[1]), heading[2]
            anchor = 'section-' + str(len(headings) + 1) if level == 2 else 'top'
            if level == 2:
                headings.append((anchor, title))
            blocks.append(f'<h{level} id="{anchor}">{inline(title)}</h{level}>')
            i += 1
            continue
        if line.startswith('|'):
            rows = []
            while i < len(lines) and lines[i].startswith('|'):
                cells = [c.strip() for c in lines[i].strip().strip('|').split('|')]
                if not all(re.fullmatch(r':?-+:?', c) for c in cells):
                    tag = 'th' if not rows else 'td'
                    rows.append('<tr>' + ''.join(f'<{tag}>{inline(c)}</{tag}>' for c in cells) + '</tr>')
                i += 1
            blocks.append('<div class="table-wrap"><table>' + ''.join(rows) + '</table></div>')
            continue
        item = re.match(r'^(?:- |\d+\. )(.+)$', line)
        if item:
            tag = 'ul' if line.startswith('- ') else 'ol'
            items = []
            pattern = r'^- (.+)$' if tag == 'ul' else r'^\d+\. (.+)$'
            while i < len(lines):
                match = re.match(pattern, lines[i])
                if not match:
                    break
                items.append('<li>' + inline(match[1]) + '</li>')
                i += 1
            blocks.append(f'<{tag}>' + ''.join(items) + f'</{tag}>')
            continue
        blocks.append('<p>' + inline(line) + '</p>')
        i += 1
    toc = '<details open><summary>部署步骤目录</summary><nav aria-label="教程目录">' + ''.join(
        f'<a href="#{anchor}">{html.escape(title)}</a>' for anchor, title in headings) + '</nav></details>'
    return '''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Singlite · 完整新部署教程</title>
<style>
:root{color-scheme:light;--accent:#7259ef}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:24px}
body{margin:0;background:#f6f7fa;color:#25304a;font-family:system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;line-height:1.85}
.page{max-width:1000px;margin:40px auto;padding:40px 48px;background:white;border:1px solid #e7eaf1;border-radius:18px}
header{display:flex;gap:12px;flex-wrap:wrap;align-items:center;padding-bottom:26px;border-bottom:1px solid #e7eaf1}
.brand{font-size:24px;font-weight:800;margin-right:auto;color:#18233c}a{color:#6346d4;text-underline-offset:3px}
header a{font-size:14px;background:#f2efff;padding:6px 12px;border-radius:8px;text-decoration:none}
h1{font-size:30px;line-height:1.4;margin:30px 0 18px;color:#17233c}h2{font-size:22px;margin:42px 0 15px;padding-top:10px;color:#17233c}h3{font-size:18px}
p,ul,ol{margin:14px 0}li{margin:6px 0}strong{font-weight:650;color:#17233c}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9em;background:#f1f2f7;padding:2px 5px;border-radius:4px;overflow-wrap:anywhere}
pre{background:#17233c;color:#e9edf7;padding:20px;border-radius:12px;overflow:auto;line-height:1.65}pre code{background:none;color:inherit;padding:0;white-space:pre;overflow-wrap:normal}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px;margin:14px 0}th,td{border:1px solid #e7eaf1;padding:10px 12px;text-align:left}th{background:#f5f3ff}
details{background:#f8f7ff;border:1px solid #ece7ff;border-radius:12px;padding:15px 18px;margin:28px 0}summary{cursor:pointer;font-weight:650}nav{display:grid;grid-template-columns:1fr 1fr;gap:5px 20px;margin-top:12px}nav a{font-size:14px;text-decoration:none}
footer{margin-top:40px;padding-top:20px;border-top:1px solid #e7eaf1;font-size:13px;color:#778198}
@media(max-width:640px){.page{margin:0;padding:24px 18px;border:0;border-radius:0}nav{grid-template-columns:1fr}h1{font-size:25px}h2{font-size:20px}pre{padding:14px}}
@media print{body{background:white}.page{max-width:none;border:0;margin:0;padding:0}header,details,footer{display:none}pre{white-space:pre-wrap;color:black;background:#f5f5f5}h2{break-after:avoid}}
</style></head><body><div class="page">
<header><span class="brand">singlite</span><a href="./singlite-panel.tar.gz">下载完整源码</a><a href="./deploy-guide.txt" download>下载中文文本版</a></header>
''' + toc + '<main>' + '\n'.join(blocks) + '''</main>
<footer>本页与源码包 README 内容同步。可直接保存本页或使用浏览器打印为 PDF。 <a href="#top">回到顶部</a></footer>
</div></body></html>'''
