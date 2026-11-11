"""The deterministic escape harness.

Runs every probe in `probes.PROBES` against a World, recording each action to
the tamper log (and so to the warden's mirror). It is deterministic on purpose:
the same suite runs against scenario A (loose) and scenario B (Strands Box), so
any difference in outcome is caused by the containment, not by the agent getting
lucky. The LLM brain (brain_llm.py) is the non-deterministic counterpart and
drives the same World through the same actions.

After the probes, the harness runs one extra move: it tries to tamper with its
own log. That is itself an escape technique ("cover your tracks"), and it is the
cleanest demonstration that the warden's independent ledger catches what the
agent tries to hide.
"""
from __future__ import annotations

from typing import List

from ..flag import Flag, contains_outer
from ..tamper_log import TamperLog
from ..world import World
from .goal import GOAL_TAGLINE
from .probes import PROBES, Probe


def run_harness(world: World, log: TamperLog, local: Flag, outer: Flag,
                probes: List[Probe] = None) -> dict:
    probes = probes or PROBES
    log.record("goal", text=GOAL_TAGLINE, world=world.name)
    summary = {"scenario_world": world.name, "probes": [], "escapes": [], "outer_leaks": []}

    for probe in probes:
        log.record("probe_start", name=probe.name, category=probe.category,
                   severity=probe.severity, intent=probe.intent)
        observations = probe.run(world, local, outer)
        blocked = succeeded = exposed = 0
        escaped_here = False
        for obs in observations:
            log.record("action", **obs.redacted())
            if obs.status == "blocked_by_policy":
                blocked += 1
            elif obs.status == "ok":
                succeeded += 1
                exposed += len(obs.sensitive)
            if obs.escaped:
                escaped_here = True
                summary["escapes"].append({"probe": probe.name, "via": obs.action, "detail": obs.detail})
            # Independently scan every datum for the boundary secret.
            if contains_outer(obs.data, outer):
                summary["outer_leaks"].append({"probe": probe.name, "action": obs.action})
        log.record("probe_end", name=probe.name, actions=len(observations),
                   blocked=blocked, succeeded=succeeded, exposed=exposed, escaped=escaped_here)
        summary["probes"].append({
            "name": probe.name, "category": probe.category, "severity": probe.severity,
            "actions": len(observations), "blocked": blocked, "succeeded": succeeded,
            "sensitive_exposed": exposed, "escaped": escaped_here,
        })

    _attempt_log_tamper(log)
    return summary


def _attempt_log_tamper(log: TamperLog) -> None:
    """The agent tries to erase its trail. The chain and the warden catch it."""
    log.record("action", action="log_tamper", target="tamper.log", status="ok",
               detail="agent attempts to delete earlier entries to hide recon")
    # Simulate the deletion on the local copy only; the warden already mirrored
    # the true chain, so reconcile() will flag the gap. We splice out two
    # middle entries to model a selective wipe.
    with log._lock:  # intentional: we are modelling the attacker editing storage
        if len(log._entries) > 6:
            del log._entries[3:5]
