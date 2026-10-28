"""The recorder: an append-only, hash-chained log of signed records, with a gate in front.

The recorder is the system that runs next to the agent. It checks every submitted record with
the same rules the independent verifier uses, writes the decision next to the record, and chains
every entry to the one before. Blocked attempts are kept: a log of what the agent tried and what
was refused is part of the evidence.
"""
from __future__ import annotations

import copy
import json
import os
import tempfile

from .canon import CanonError, canonical, digest
from .evaluate import Replay
from .spec import FORMAT, GENESIS, now_ts

KIND_TO_APPLY = {"grant": "apply_grant", "action": "apply_action", "revocation": "apply_revocation"}
ALLOW_VERDICTS = {"GRANT_OK", "IN_AUTHORITY", "REVOCATION_EFFECTIVE"}


def entry_hash(entry: dict) -> str:
    return digest({k: v for k, v in entry.items() if k != "hash"})


class TrailError(Exception):
    pass


class Trail:
    def __init__(self, clock=None) -> None:
        self.clock = clock
        self.entries: list[dict] = []
        self.anchors: list[dict] = []
        self.replay = Replay()

    # ----- writing -----
    def submit(self, env: dict, *, _gate_override: str | None = None) -> dict:
        """Check an envelope, record it with the gate decision, return {entry, result}.

        _gate_override exists to demonstrate a dishonest operator in tests and the demo; it writes a
        gate decision that the checks did not make. The independent verifier is built to catch that."""
        if not isinstance(env, dict):
            raise TrailError("record must be an object")
        env = copy.deepcopy(env)  # the caller keeps no handle on what the recorder holds
        kind = env.get("kind")
        if kind not in KIND_TO_APPLY:
            raise TrailError(f"unknown record kind {kind!r}")
        try:
            canonical(env)  # refuse anything that cannot be hashed identically everywhere, before any state changes
        except CanonError as e:
            raise TrailError(f"record cannot be canonicalised: {e}") from e
        seq = len(self.entries)
        recorded_at = now_ts(self.clock)
        result = getattr(self.replay, KIND_TO_APPLY[kind])(env, seq, recorded_at)
        decision = "ALLOWED" if result["verdict"] in ALLOW_VERDICTS else "BLOCKED"
        if _gate_override:
            decision = _gate_override
        entry = {
            "seq": seq,
            "prev": self.entries[-1]["hash"] if self.entries else GENESIS,
            "recorded_at": recorded_at,
            "envelope": env,
            "gate": {"decision": decision, "reasons": list(result["reasons"])},
        }
        entry["hash"] = entry_hash(entry)
        self.entries.append(entry)
        return {"entry": copy.deepcopy(entry), "result": copy.deepcopy(result)}

    def head(self) -> dict | None:
        if not self.entries:
            return None
        e = self.entries[-1]
        return {"seq": e["seq"], "hash": e["hash"]}

    # ----- persistence -----
    def to_bundle(self) -> dict:
        return {"format": FORMAT, "entries": copy.deepcopy(self.entries), "anchors": copy.deepcopy(self.anchors)}

    def save(self, path: str) -> None:
        data = json.dumps(self.to_bundle(), indent=1, ensure_ascii=False) + "\n"
        d = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str, clock=None) -> "Trail":
        """Load a saved log and replay it to rebuild state. Refuses a log whose chain is broken."""
        with open(path, encoding="utf-8") as f:
            bundle = json.load(f)
        t = cls(clock)
        prev = GENESIS
        for i, e in enumerate(bundle["entries"]):
            if e.get("seq") != i or e.get("prev") != prev or e.get("hash") != entry_hash(e):
                raise TrailError(f"log is broken at entry {i}; run the verifier")
            prev = e["hash"]
            getattr(t.replay, KIND_TO_APPLY[e["envelope"]["kind"]])(e["envelope"], i, e["recorded_at"])
            t.entries.append(e)
        t.anchors = list(bundle.get("anchors", []))
        return t
