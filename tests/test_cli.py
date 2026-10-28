import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(*args):
    return subprocess.run([sys.executable, "-m", "authority_trail", *args], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", timeout=120)


def test_cli_end_to_end(tmp_path):
    d = str(tmp_path / "out")
    r = run("demo", "--out", d)
    assert r.returncode == 0 and "REFUSED" in r.stdout
    pin = open(os.path.join(d, "PRINCIPAL_KEY_ID.txt")).read().strip()
    good = os.path.join(d, "trail.json")
    v = run("verify", good, "--pin", pin)
    assert v.returncode == 0 and "RESULT: CLEAN" in v.stdout
    assert run("verify", good, "--pin", "0" * 32).returncode == 3
    t1 = str(tmp_path / "t1.json")
    run("tamper", good, "--out", t1)
    v = run("verify", t1)
    assert v.returncode == 1 and "HASH_MISMATCH at entry 1" in v.stdout
    t2 = str(tmp_path / "t2.json")
    run("tamper", good, "--out", t2, "--mode", "rehash")
    v = run("verify", t2)
    assert v.returncode == 3 and "SIGNATURE_INVALID at entry 1" in v.stdout
    assert run("verify", os.path.join(d, "trail_rogue_operator.json")).returncode == 3
    m = run("memo", good, "--pin", pin)
    assert "What this memo does not establish" in m.stdout and "WITHIN the structured limits" in m.stdout
    j = json.loads(run("verify", good, "--json").stdout)
    assert j["summary"]["in_authority"] == 5
    assert run("verify", str(tmp_path / "missing.json")).returncode == 2


def test_anchor_export_and_eth_data(tmp_path):
    d = str(tmp_path / "out")
    run("demo", "--out", d)
    good = os.path.join(d, "trail.json")
    e = run("anchor-eth-data", good)
    assert e.returncode == 0 and "data  0x415431" in e.stdout
    assert run("anchor-export", good, "--dir", str(tmp_path / "x")).returncode == 2  # no OTS anchor yet
    rec = run("anchor-eth-record", good, "--tx", "0x" + "ab" * 32)
    assert rec.returncode == 0
    v = run("verify", good)
    assert "anchor ethereum" in v.stdout and "ATTESTED_UNCHECKED" in v.stdout


def test_head_checkpoint_keygen_and_hostile_input(tmp_path):
    d = str(tmp_path / "out")
    run("demo", "--out", d)
    good = os.path.join(d, "trail.json")
    head = run("head", good).stdout.strip()
    assert head.startswith("13:") and run("verify", good, "--expect-head", head).returncode == 0
    assert run("verify", good, "--expect-head", "13:" + "0" * 64).returncode == 3
    assert run("verify", good, "--require-anchor").returncode == 3
    key = str(tmp_path / "k.seed")
    assert run("keygen", "--name", "x", "--out", key).returncode == 0
    again = run("keygen", "--name", "x", "--out", key)
    assert again.returncode == 2 and "refusing" in again.stderr
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    r = run("verify", str(deep))
    assert r.returncode == 2 and "cannot read" in r.stderr
    notjson = tmp_path / "x.json"
    notjson.write_text("not json", encoding="utf-8")
    assert run("memo", str(notjson)).returncode == 2
