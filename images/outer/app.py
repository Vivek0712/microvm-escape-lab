"""Outer warden image - the second containment layer.

Holds the outer flag, mirrors the inner cage's log into an independent ledger,
and renders the verdict. The flag route is gated on a warden key the inner image
never receives, so a well-contained cage can never pull it. /observe is the
mirror sink; /finish triggers reconciliation and stores the verdict for the
operator to read with `mvm call <warden-id> /verdict`.
"""
from __future__ import annotations

import json
import os

from microvm_hooks import HookApp

from lab.flag import Flag
from lab.tamper_log import TamperLog, WardenLedger

app = HookApp()

# The outer flag is created per launch and passed in via runHookPayload so the
# operator (not the image) controls it. It is never sent to the inner cage.
STATE = {"outer": None, "ledger": WardenLedger(), "verdict": None}
WARDEN_KEY = os.environ.get("WARDEN_KEY", "WARDEN-KEY")


@app.on_run
def run(ctx):
    cfg = json.loads(ctx.get("runHookPayload") or "{}")
    STATE["outer"] = Flag("outer", cfg["outer_token"], "held by warden")
    app.job.phase("watching")


@app.route("POST", "/observe")
def observe(body, headers):
    ok = STATE["ledger"].observe(body)
    return 200, {"accepted": ok}


@app.route("GET", "/flag")
def flag(body, headers):
    key = headers.get("X-Warden-Key") or headers.get("x-warden-key")
    if key == WARDEN_KEY and STATE["outer"]:
        return 200, {"flag": STATE["outer"].marker}
    return 403, {"error": "inner cage holds no warden key"}


@app.route("POST", "/finish")
def finish(body, headers):
    summary = body or {}
    recon = STATE["ledger"].reconcile(STATE["ledger"].chain())  # self-consistent view
    chain_ok = TamperLog.verify(STATE["ledger"].chain())["ok"]
    STATE["verdict"] = {
        "contained": not summary.get("escapes") and not summary.get("outer_leaks"),
        "escape_events": summary.get("escapes", []),
        "outer_flag_leaks": summary.get("outer_leaks", []),
        "entries_mirrored": recon["mirrored"],
        "warden_chain_intact": chain_ok,
        "rejected_entries": len(STATE["ledger"].rejected),
    }
    return 200, {"ok": True}


@app.route("GET", "/verdict")
def verdict(body, headers):
    return 200, {"verdict": STATE["verdict"], "ledger_len": len(STATE["ledger"].chain())}


if __name__ == "__main__":
    app.serve(port=int(os.environ.get("PORT", "8080")))
