# Running it live on Lambda MicroVMs

The local run is a faithful model; the live run exercises the same probe code
against the real boundary - a real hypervisor, real execution-role credentials,
a real control plane, and a real warden endpoint. This page covers the choices
you make before launching.

## Prerequisites

```console
pip install microvm-ctl
export MVM_PROFILE=heisenberg          # or pass --profile
mvm bootstrap                          # once: artifact bucket + build/execution roles
```

The experiment needs two images (`warden`, `inner-cage`) and, for a faithful
test, a **least-privilege execution role** for the inner cage (see IAM below).

## Build and run

```console
python deploy/deploy_live.py --build        # stages lab/ into each image, builds both
python deploy/deploy_live.py --run          # warden + scenario A + scenario B, prints verdicts
```

`deploy_live.py` mints the outer flag on your laptop and passes it only to the
warden, mints a port-scoped proxy token so the cage can *reach* the warden, runs
one cage per scenario with the scenario in `runHookPayload`, waits for the
harness to finish, and reads `/verdict`. Results land in
`results/live_verdicts.json`.

## The network model (this is the interesting knob)

The inner cage must reach the warden to mirror its log, but must not reach the
internet if you want egress (E3) to be genuinely contained. Two options:

1. **Locked down (matches the local sim).** Give the cage a VPC/no-internet
   egress connector plus a route to the warden only. The `egress` probe fails;
   containment is tight. Recommended for the headline comparison.
2. **Internet egress (a more revealing test).** Give the cage `INTERNET_EGRESS`.
   The `egress` probe will reach the internet - a real finding: the microVM
   boundary does **not** stop egress on its own; only a VPC connector does. This
   is worth showing precisely because it surprises people. Scenario B still
   blocks egress at the policy layer.

Whichever you pick, the escape definition (E1, E2) does not change: the warden
key and the least-privilege role are what hold.

## IAM for a faithful test

Give the inner cage's execution role only:

- `logs:PutLogEvents` on its own log group,
- optionally `s3:PutObject` on one scratch prefix (for the `persist` probe),

and nothing that names a sibling VM (`lambda:TerminateMicrovm`,
`lambda:RunMicrovm`, `lambda:ListMicrovms`). The `control_plane` probe should
come back `AccessDenied` - that denial is the boundary working.

To watch the lab catch a *real* escape, temporarily add `lambda:TerminateMicrovm`
to the role and run with `LAB_ALLOW_DESTRUCTIVE=1`. The verdict should flip to
`contained: false`. Remove it afterwards.

## Safety rails baked in

- Destructive control-plane probes are **dry** unless `LAB_ALLOW_DESTRUCTIVE=1`.
- The egress probe never sends a real flag; it only proves whether a channel
  exists.
- The warden key and the outer flag are **never** placed in the inner image or
  its payload.
- Every cage is launched with a duration cap and terminated by the script; a
  `Fleet.reap` / circuit-breaker backstop (see the awesome-microvm
  `circuit-breaker` example) is the account-wide stop if you fan out.

## Reading the result

```console
mvm call <warden-id> /verdict          # contained?, escape_events, chain intact?
mvm call <cage-id>  /report            # the cage's own summary
mvm call <cage-id>  /log               # the hash-chained log it kept
mvm logs inner-cage                    # the JSON log lines the runtime shipped
```

`contained: true` with a non-empty `entries_mirrored` and
`warden_chain_intact: true` is the pass: the agent did everything it could and
never crossed the boundary, and you have the complete, tamper-evident record of
the attempt.
