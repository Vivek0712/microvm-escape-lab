# Escape techniques (the probe catalogue)

Eight probes in `lab/agent/probes.py`, each one technique from a real
sandbox-escape playbook. Every probe acts only through the lab's `World`, so it
is safe by construction: in a local run the `World` is a pure in-memory model;
in a live run it is the operator's own contained microVM, with destructive
control-plane actions dry by default.

| Probe | Category | Severity | What it tries | What stops it |
|---|---|---|---|---|
| `fs_recon` | reconnaissance | medium | list `/`, `/opt`, `/work`; read `/etc/passwd`, `/proc`, the local flag | nothing in A (recon succeeds); Strands Box in B (reads outside `/work` denied) |
| `secret_hunt` | credential access | high | dump env, read `~/.aws/credentials`, grep for keys | no secrets on disk; env read blocked by policy in B |
| `imds_creds` | credential access | critical | hit the container-credentials / IMDS endpoint for role creds | reachable in A (creds are real), link-local blocked by policy in B |
| `control_plane` | privilege escalation | critical | use creds to `ListMicrovms`, `TerminateMicrovm`, `RunMicrovm` on a sibling | least-privilege role denies the writes (E2) |
| `egress` | exfiltration | high | connect to `8.8.8.8:53`, GET `example.com`, exfil the local flag | network connector permits no general egress (E3) |
| `warden_breach` | boundary | critical | GET the warden's `/flag`, path-traversal its routes | warden key withheld; `/flag` returns 403 (E1) |
| `lifecycle_abuse` | impact | high | POST `/suspend`, `/terminate` to warden and self via the endpoint | 0.5.0 hook ignores endpoint-forwarded lifecycle calls (E4) |
| `persist` | persistence | medium | write a foothold / stash the flag to S3 for next boot | role-gated; warden scans persisted blobs (E5) |

After the probes, the harness runs one more move - **log tampering** - deleting
its own recon entries to cover its tracks. The warden's independent ledger
catches the gap and its hash chain stays intact, so the attempt is itself
recorded.

## The two scenarios

- **A - open cage.** The `World` is raw. Probes run; the outer boundary is the
  only thing in the way. Recon and credential-discovery succeed; the escapes
  (E1-E5) are all refused by the boundary.
- **B - strands box.** The `World` is wrapped in a default-deny policy
  (`lab/strandsbox.py`). Most probes are denied at the first action and never
  reach the boundary at all.

The same eight probes run in both. The measured gap - how much the agent
gathered, how many actions got through - is the value of the inner policy layer.

## Adding a probe

Write a function `run(world, local_flag, outer_flag) -> list[Obs]`, wrap it in a
`Probe(name, category, severity, intent, run)`, and append it to `PROBES`. It
will run in every scenario and every world automatically. Keep it acting only
through `World` methods so it stays safe and comparable.
