import json
import os
import shutil
import subprocess

import pytest

from authority_trail import demo
from authority_trail.verify import verify_bundle

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = shutil.which("node")


def run_js(tmp_path, bundle):
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
    out = subprocess.run([NODE, os.path.join(ROOT, "tests", "web_check.js"),
                          os.path.join(ROOT, "web", "verify.html"), str(p)],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_browser_checker_agrees_with_python_verifier(scenario, tmp_path):
    trail, _, _ = scenario
    good = trail.to_bundle()
    js = run_js(tmp_path, good)
    assert js["problems"] == [] and set(js["sig"]) == {"valid"}
    # an edit: both implementations name the same first broken entry
    bad = demo.tamper_amount(good)
    js = run_js(tmp_path, bad)
    py = verify_bundle(bad)
    assert js["first"] == py["chain"]["first_broken_seq"] and js["first"] is not None
    # a careful attacker who rebuilds the hashes: chain looks fine, the edited entry's signature fails in both
    sneaky = demo.tamper_rehash(good)
    js = run_js(tmp_path, sneaky)
    py = verify_bundle(sneaky)
    assert js["problems"] == [] and py["chain"]["ok"]
    assert [i for i, s in enumerate(js["sig"]) if s != "valid"] == py["signature_problem_seqs"]


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_canonical_form_matches_for_non_ascii_and_key_order(clock, tmp_path):
    from authority_trail.keys import Party
    from authority_trail.spec import action_body, grant_body, make_envelope, permission, ref_of
    from authority_trail.trail import Trail
    gr, ge = Party("P Ω"), Party("A naïve")
    t = Trail(clock)
    g = grant_body(gr, ge, title="t ☃", text="w \U0001F600", purpose="p", not_before=clock.iso(seconds=-5),
                   expires_at=clock.iso(seconds=500), permissions=[permission("note")], grant_id="G-1")
    t.submit(make_envelope(gr, "grant", g))
    params = {"z": 1, "￮": 2, "\U0001F600": 3, "a\"b": "line\nbreak\t\u0001", "é": ["x", None, True]}
    t.submit(make_envelope(ge, "action", action_body(ref_of(g), "note", params, clock.iso(), action_id="A-1")))
    js = run_js(tmp_path, t.to_bundle())
    assert js["problems"] == [] and set(js["sig"]) == {"valid"}


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_page_renders_sample_and_detects_in_page_edit():
    out = subprocess.run([NODE, os.path.join(ROOT, "tests", "web_render.js"), os.path.join(ROOT, "web", "verify.html")],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "clean render ok" in out.stdout and "tamper render ok" in out.stdout
