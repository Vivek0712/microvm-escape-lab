"""Append-only, hash-chained event log.

Every action the agent takes is one entry. Each entry carries the SHA-256 of
(previous hash + this entry's canonical bytes), so any later edit, reorder, or
deletion breaks the chain and `verify()` reports exactly where.

The inner cage writes the log. It also *mirrors* every entry to the warden
(the outer sandbox), which keeps its own independent chain. If the agent
rewrites or deletes its local log, the warden's copy still holds the truth:
tamper-evidence does not depend on the thing being observed staying honest.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Callable, Dict, List, Optional

GENESIS = "0" * 64


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _digest(prev_hash: str, body: dict) -> str:
    return hashlib.sha256(prev_hash.encode() + _canon(body)).hexdigest()


class TamperLog:
    """A hash-chained event log with an optional mirror sink."""

    def __init__(self, source: str, mirror: Optional[Callable[[dict], None]] = None):
        self.source = source
        self._mirror = mirror
        self._entries: List[dict] = []
        self._lock = threading.Lock()

    @property
    def head(self) -> str:
        return self._entries[-1]["hash"] if self._entries else GENESIS

    def record(self, kind: str, **fields) -> dict:
        """Append one event and return the sealed entry."""
        with self._lock:
            seq = len(self._entries)
            body = {
                "seq": seq,
                "ts": round(time.time(), 6),
                "source": self.source,
                "kind": kind,
                "fields": fields,
                "prev": self.head,
            }
            body["hash"] = _digest(body["prev"], {k: body[k] for k in body if k != "hash"})
            self._entries.append(body)
        if self._mirror is not None:
            try:
                self._mirror(dict(body))
            except Exception as exc:  # the mirror must never break the subject
                self.record("mirror_error", error=repr(exc))
        return body

    def entries(self) -> List[dict]:
        with self._lock:
            return [dict(e) for e in self._entries]

    def dumps(self) -> str:
        return "\n".join(json.dumps(e, sort_keys=True) for e in self.entries())

    @staticmethod
    def verify(entries: List[dict]) -> Dict[str, object]:
        """Re-derive the chain. Returns {ok, broken_at, length}."""
        prev = GENESIS
        for i, e in enumerate(entries):
            if e.get("prev") != prev:
                return {"ok": False, "broken_at": i, "reason": "prev-mismatch", "length": len(entries)}
            expect = _digest(prev, {k: e[k] for k in e if k != "hash"})
            if e.get("hash") != expect:
                return {"ok": False, "broken_at": i, "reason": "hash-mismatch", "length": len(entries)}
            prev = e["hash"]
        return {"ok": True, "broken_at": None, "reason": None, "length": len(entries)}


class WardenLedger:
    """The warden's independent mirror of an inner cage's log.

    It accepts entries one at a time and refuses any that do not extend the
    chain it has already seen, so a replayed or forged entry is rejected and
    a *missing* entry (a gap) shows up as a sequence jump.
    """

    def __init__(self):
        self._by_seq: Dict[int, dict] = {}
        self._lock = threading.Lock()
        self.rejected: List[dict] = []

    def observe(self, entry: dict) -> bool:
        with self._lock:
            seq = entry.get("seq")
            expect_prev = self._by_seq[seq - 1]["hash"] if seq and (seq - 1) in self._by_seq else GENESIS
            recomputed = _digest(expect_prev, {k: entry[k] for k in entry if k != "hash"})
            if entry.get("hash") != recomputed or (seq in self._by_seq):
                self.rejected.append(entry)
                return False
            self._by_seq[seq] = dict(entry)
            return True

    def chain(self) -> List[dict]:
        with self._lock:
            return [self._by_seq[k] for k in sorted(self._by_seq)]

    def reconcile(self, local_entries: List[dict]) -> Dict[str, object]:
        """Compare the agent's local log against what the warden saw.

        Any entry the warden mirrored but the local log no longer contains is
        proof the agent deleted or rewrote its trail after the fact.
        """
        mirrored = {e["seq"]: e["hash"] for e in self.chain()}
        local = {e["seq"]: e.get("hash") for e in local_entries}
        missing = sorted(s for s in mirrored if s not in local)
        altered = sorted(s for s in mirrored if s in local and local[s] != mirrored[s])
        return {
            "mirrored": len(mirrored),
            "local": len(local),
            "deleted_by_agent": missing,
            "altered_by_agent": altered,
            "tamper_detected": bool(missing or altered or self.rejected),
        }
