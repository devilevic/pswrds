#!/usr/bin/env python3
"""Builds the public/ folder: everything that goes on the web server.

- src/pswrds.html is the app source. It has no <html>/<head>/<body> tags because the
  claude.ai preview adds them; this script adds them (plus icons and app manifest) for real hosting.
- server/api.php and server/.htaccess are copied as they are.
- static/ (icons, manifest, service worker) is copied as it is.

Upload the contents of public/ to public_html on your hosting.
"""
import html, json, re, shutil, time
from pathlib import Path

root = Path(__file__).parent
pub = root / "public"
if pub.exists():
    shutil.rmtree(pub)   # start clean, so renamed or removed files don't linger
pub.mkdir()
SITE = "https://pswrds.com/"
# Pages listed in sitemap.xml (the statistics page is deliberately left out).
SITEMAP = [("", root / "src" / "pswrds.html"), ("faq.html", None), ("duress-passphrase.html", None),
           ("security.html", None),
           ("terms.html", None), ("privacy.html", None)]

def faq_schema(page):
    """Structured data (schema.org FAQPage) from the <details class="q"> questions on a page."""
    items = []
    for q, a in re.findall(r'<details class="q"[^>]*>\s*<summary>(.*?)</summary>(.*?)</details>', page, re.S):
        a = re.sub(r"<figure.*?</figure>", " ", a, flags=re.S)
        a = re.sub(r"</(p|li)>", "\\g<0> ", a)
        text = lambda x: re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", x))).strip()
        items.append({"@type": "Question", "name": text(q), "acceptedAnswer": {"@type": "Answer", "text": text(a)}})
    data = {"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": items}
    return '<script type="application/ld+json">' + json.dumps(data, ensure_ascii=False).replace("</", "<\\/") + "</script>"

HEAD = """<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="description" content="A zero-knowledge password manager. Your passwords are encrypted on your own device, so we can't read them. No email or phone number needed, and the first 10 records are free.">
<link rel="canonical" href="https://pswrds.com/">
<meta property="og:type" content="website">
<meta property="og:site_name" content="pswrds">
<meta property="og:url" content="https://pswrds.com/">
<meta property="og:title" content="pswrds: a zero-knowledge password manager">
<meta property="og:description" content="A zero-knowledge password manager. Your passwords are encrypted on your own device, so we can't read them. No email or phone number needed, and the first 10 records are free.">
<meta property="og:image" content="https://pswrds.com/img/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebApplication","name":"pswrds","url":"https://pswrds.com/","applicationCategory":"SecurityApplication","operatingSystem":"Any (web browser)","description":"A zero-knowledge password manager. Your passwords are encrypted on your own device, so we can't read them. No email or phone number needed, and the first 10 records are free.","offers":[{"@type":"Offer","price":"0","priceCurrency":"USD","description":"10 records per wallet"},{"@type":"Offer","price":"20","priceCurrency":"USD","description":"Unlimited records, one-time payment"}]}</script>
<meta name="theme-color" content="#E8EBEE" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0E1318" media="(prefers-color-scheme: dark)">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="pswrds">
<link rel="icon" href="favicon.ico" sizes="32x32">
<link rel="icon" href="img/icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="img/apple-touch-icon.png">
<link rel="manifest" href="manifest.webmanifest">"""

body = (root / "src" / "pswrds.html").read_text(encoding="utf-8")
page = '<!doctype html>\n<html lang="en">\n<head>\n' + HEAD + "\n</head>\n<body>\n" + body + "\n</body>\n</html>\n"
(pub / "index.html").write_text(page, encoding="utf-8")

for name in ("api.php", ".htaccess"):
    shutil.copyfile(root / "server" / name, pub / name)
for f in sorted((root / "static").iterdir()):
    if f.name.startswith(".") and f.name != ".well-known":   # .well-known/security.txt is published
        continue
    if f.is_file() and f.suffix == ".html" and "<!-- faq-schema" in f.read_text(encoding="utf-8"):
        page = f.read_text(encoding="utf-8")
        page = re.sub(r"<!-- faq-schema[^>]*-->", lambda m: faq_schema(page), page)
        (pub / f.name).write_text(page, encoding="utf-8")
    elif f.is_file():
        shutil.copyfile(f, pub / f.name)
    elif f.is_dir():  # e.g. fonts/
        shutil.copytree(f, pub / f.name, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".*"))

urls = []
for path, src in SITEMAP:
    src = src or root / "static" / path
    day = time.strftime("%Y-%m-%d", time.gmtime(src.stat().st_mtime))
    urls.append(f"  <url><loc>{SITE}{path}</loc><lastmod>{day}</lastmod></url>")
(pub / "sitemap.xml").write_text('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                                 + "\n".join(urls) + "\n</urlset>\n", encoding="utf-8")

print("Built public/:", ", ".join(sorted(p.name for p in pub.iterdir())))
