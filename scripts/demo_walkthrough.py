#!/usr/bin/env python3
"""Runs the demo commands in order for a screen recording, with a banner and a pause between steps.

    python scripts/demo_walkthrough.py            # press Enter between steps
    python scripts/demo_walkthrough.py --pause 6  # or wait 6 seconds between steps

Everything is written to ./walkthrough_out (ignored by git). Data is fictional.
"""
import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(os.getcwd(), "walkthrough_out")


def run(args, banner, expect=0):
    print("\n" + "=" * 70)
    print(banner)
    print("=" * 70)
    print("$ python -m authority_trail " + " ".join(args).replace(OUT, "walkthrough_out"))
    sys.stdout.flush()
    r = subprocess.run([sys.executable, "-m", "authority_trail", *args], cwd=ROOT)
    sys.stdout.flush()
    if r.returncode != expect:
        sys.exit(f"Stopped: expected exit code {expect}, got {r.returncode}. Fix this before recording.")
    return r.returncode


def wait(pause):
    if pause:
        time.sleep(pause)
    else:
        input("\n[Enter for next step] ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pause", type=float, default=0)
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    good = os.path.join(OUT, "trail.json")
    run(["demo", "--out", OUT], "1. Fictional scenario: grants, requested actions, refusals, revocation")
    pin = open(os.path.join(OUT, "PRINCIPAL_KEY_ID.txt")).read().strip()
    wait(a.pause)
    run(["memo", good, "--pin", pin], "2. The authority memo a lawyer would read")
    wait(a.pause)
    run(["verify", good, "--pin", pin], "3. Independent verification")
    wait(a.pause)
    run(["tamper", good, "--out", os.path.join(OUT, "edited.json")], "4. Attack: edit one payment amount")
    run(["verify", os.path.join(OUT, "edited.json")], "   Verify the edited copy", expect=1)
    wait(a.pause)
    run(["tamper", good, "--out", os.path.join(OUT, "sneaky.json"), "--mode", "rehash"], "5. Careful attack: edit, then rebuild every hash")
    run(["verify", os.path.join(OUT, "sneaky.json")], "   Verify the rebuilt copy", expect=3)
    wait(a.pause)
    run(["verify", os.path.join(OUT, "trail_rogue_operator.json")], "6. Dishonest operator records an over-limit request as allowed", expect=3)
    wait(a.pause)
    run(["anchor-eth-data", good], "7. Anchoring: the commitment for an Ethereum test network (Bitcoin: anchor-stamp)")
    print("\nNext: open web/verify.html in the browser and drop walkthrough_out/trail.json on it.")


if __name__ == "__main__":
    main()
