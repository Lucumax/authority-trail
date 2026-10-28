"""A short end-to-end use of the library: grant, act, get refused, revoke, verify.

Run from the repository root:  python examples/quickstart.py
All names are fictional. The keys are random and exist only in this process.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from authority_trail import memo
from authority_trail.keys import Party
from authority_trail.spec import (action_body, grant_body, make_envelope, now_ts, permission, ref_of, revocation_body)
from authority_trail.trail import Trail
from authority_trail.verify import verify_bundle

company, agent = Party("Example Co (fictional)"), Party("Payables Agent")
t = lambda **d: (datetime.now(timezone.utc) + timedelta(**d)).strftime("%Y-%m-%dT%H:%M:%SZ")

trail = Trail()

# 1. The company signs a grant: exact wording, window, limits. The wording's SHA-256 is part of what is signed.
grant = grant_body(
    company, agent, title="Pay supplier invoices",
    text="Example Co lets its Payables Agent pay invoices from Supplier Ltd, up to USD 500.00 each, for 24 hours.",
    purpose="Supplier payments", not_before=t(minutes=-1), expires_at=t(hours=24),
    permissions=[permission("pay_invoice", max_amount=50000, currency="USD", counterparties=["Supplier Ltd"])],
    grant_id="G-1")
trail.submit(make_envelope(company, "grant", grant))
GRANT = ref_of(grant)  # later records point at the grant by the hash of its body

# 2. The agent signs each action it takes; the recorder checks it and writes the decision down.
def pay(amount, who, aid):
    body = action_body(GRANT, "pay_invoice", {"amount": amount, "currency": "USD", "counterparty": who}, now_ts(), action_id=aid)
    r = trail.submit(make_envelope(agent, "action", body))["result"]
    print(f"{aid}: {amount/100:>8.2f} to {who:<12} -> {r['verdict']} {r['reasons']}")

pay(20000, "Supplier Ltd", "A-1")          # inside the grant
pay(90000, "Supplier Ltd", "A-2")          # over the per-invoice limit: refused, but kept on record
pay(10000, "Other Corp", "A-3")            # not on the counterparty list: refused

# 3. The company withdraws the authority. Anything recorded after this entry is outside it.
trail.submit(make_envelope(company, "revocation", revocation_body(GRANT, "Contract ended", now_ts(), rev_id="R-1")))
pay(5000, "Supplier Ltd", "A-4")           # refused: revoked

# 4. Anyone can verify the saved bundle, trusting only the company's key they obtained elsewhere.
bundle = trail.to_bundle()
report = verify_bundle(bundle, pinned_keys=[company.key_id])
print("\nverifier says:", report["status"], report["summary"])
print(memo.render(report, bundle)[:700], "...")
