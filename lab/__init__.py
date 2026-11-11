"""microvm-escape-lab: a two-layer containment experiment for escaping agents.

Inner microVM (the cage) runs an agent whose only goal is to escape. Outer
microVM (the warden) holds the flag, mirrors the log, and renders the verdict.
Scenario A runs the agent loose; scenario B runs it inside a Strands-Box-style
policy. Everything it does is recorded in a hash-chained, warden-mirrored log.
"""
from .flag import Flag, mint  # noqa: F401
from .tamper_log import TamperLog, WardenLedger  # noqa: F401
from .warden import Warden  # noqa: F401
from .world import SimWorld, PolicyWorld  # noqa: F401
from .strandsbox import StrandsBoxPolicy  # noqa: F401

__version__ = "0.1.0"
