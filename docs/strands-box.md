# Strands Box as the inner cage

Scenario B runs the agent inside **Strands Box**: a per-action policy that
decides every file touch, command, and network call before it happens. This is
the same idea as the awesome-microvm
[`strands-box`](https://github.com/Vivek0712/awesome-microvm/tree/main/examples/strands-box)
example, where a Dogwood policy governs each command and file an agent inside a
Lambda MicroVM touches.

The lab ships a self-contained, Dogwood-style policy (`lab/strandsbox.py`) so it
has no hard dependency on the Strands runtime while modelling exactly the control
it provides. It is default-deny with a task-scoped allowlist:

- **files:** read/write only under `/work` and `/tmp/agent`;
- **exec:** only `python3`, `ls`, `cat`, `echo`, `id`;
- **network:** only the warden, and only its `/observe`, `/submit`, `/status`
  routes;
- **everything else** - env dumps, the metadata endpoint, direct AWS calls,
  lifecycle control, off-box persistence - is denied.

## How it plugs in

`PolicyWorld(inner_world, StrandsBoxPolicy())` wraps the `World` the probes act
on. Before forwarding any action it calls `policy.decide(action, target, meta)`;
a denied action returns a `blocked_by_policy` observation and never reaches the
boundary. The probes are unchanged - they just mostly bounce.

## Swapping in the real Strands runtime

To run the genuine Strands Box instead of the modelled policy:

1. Build the inner image from the awesome-microvm `strands-box` example's
   runtime (the Dogwood policy engine and the Strands agent loop).
2. Implement a `World` whose methods route through the Strands tool-call path, so
   each probe action becomes a Strands tool invocation the policy adjudicates.
3. Keep the same `TamperLog` mirror to the warden so the record and verdict are
   unchanged.

The experiment's structure - two flags, two layers, one tamper-evident log, the
A/B comparison - stays identical. Only the implementation of the inner cage
changes.
