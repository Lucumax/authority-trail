#!/usr/bin/env python3
"""Embed examples/sample/trail.json into web/verify.html so the page's sample button works offline.

    python scripts/embed_sample.py
"""
import json
import os
import re

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(root, "examples", "sample", "trail.json"), encoding="utf-8") as f:
    data = json.load(f)
page = os.path.join(root, "web", "verify.html")
with open(page, encoding="utf-8") as f:
    html = f.read()
blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\/")
html = re.sub(r'(<script id="sample-data">)window\.SAMPLE = .*?;(</script>)',
              lambda m: f'{m.group(1)}window.SAMPLE = {blob};{m.group(2)}', html, flags=re.S)
with open(page, "w", encoding="utf-8", newline="\n") as f:
    f.write(html)
print("embedded", len(blob), "bytes")
