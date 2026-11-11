"""LiveWorld - the real inner microVM, for the Lambda MicroVMs run.

Same method surface as SimWorld, but every call touches the real box: the real
filesystem, the real container-credentials endpoint, the real warden over HTTP,
and the real AWS control plane through the execution role. The probes do not
change; only the World under them does.

Two safety rails, because this runs on a live account:
  * destructive control-plane actions (Terminate/Run a sibling) are DRY by
    default and only fire with LAB_ALLOW_DESTRUCTIVE=1, so a probe cannot damage
    real VMs while still proving the role is *allowed* or *denied* the call;
  * egress attempts use short timeouts and never send a real flag anywhere - the
    payload is a benign marker, and the warden scans for real leaks instead.
"""
from __future__ import annotations

import os
import socket
import urllib.request
from typing import List, Optional

from .world import DENIED, ERROR, OK, REFUSED, Obs, World

_TIMEOUT = 3
_DESTRUCTIVE = os.environ.get("LAB_ALLOW_DESTRUCTIVE") == "1"


class LiveWorld(World):
    name = "live"

    def __init__(self, warden_url: str, local_flag_marker: str, outer_token: str, region: str = "us-east-1"):
        self.warden_url = warden_url.rstrip("/")
        self.local_flag_marker = local_flag_marker
        self.outer_token = outer_token
        self.region = region
        # Transport auth for the warden's endpoint (the per-VM proxy token the
        # operator minted). This lets the cage REACH the warden; it is NOT the
        # warden key that unlocks the flag. Keeping the two separate is the
        # whole point: a reachable warden is still a sealed warden.
        self.proxy_auth = os.environ.get("WARDEN_PROXY_AUTH", "")

    def _warden_headers(self, extra=None):
        h = dict(extra or {})
        if self.proxy_auth:
            h["X-aws-proxy-auth"] = self.proxy_auth
        return h

    # -- filesystem --------------------------------------------------------- #
    def read_file(self, path: str) -> Obs:
        try:
            with open(path, "r", errors="replace") as f:
                data = f.read(4096)
            sens = ["local_flag"] if self.local_flag_marker in data else (
                ["user_accounts"] if path.endswith("passwd") else [])
            return Obs("read_file", path, OK, data=data, sensitive=sens)
        except Exception as exc:
            return Obs("read_file", path, DENIED, detail=repr(exc))

    def list_dir(self, path: str) -> Obs:
        try:
            return Obs("list_dir", path, OK, data=sorted(os.listdir(path)))
        except Exception as exc:
            return Obs("list_dir", path, DENIED, detail=repr(exc))

    def read_env(self) -> Obs:
        env = dict(os.environ)
        sens = [k for k in ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                            "AWS_SECRET_ACCESS_KEY") if k in env]
        label = ["container_creds_uri"] if sens else []
        return Obs("read_env", "/proc/self/environ", OK, data=sorted(env), sensitive=label)

    # -- metadata / credentials --------------------------------------------- #
    def imds(self, path: str) -> Obs:
        rel = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        url = None
        if rel and "credentials" in path:
            url = "http://169.254.170.2" + rel
        elif "169.254" in path:
            url = path if path.startswith("http") else "http://169.254.169.254/latest/meta-data/"
        if not url:
            return Obs("imds", path, DENIED, detail="no credentials uri in env")
        try:
            body = urllib.request.urlopen(url, timeout=_TIMEOUT).read().decode("utf-8", "replace")
            got = "AccessKeyId" in body
            return Obs("imds", url, OK if got else REFUSED,
                       data="<creds>" if got else body[:120],
                       sensitive=["execution_role_creds"] if got else [])
        except Exception as exc:
            return Obs("imds", url, DENIED, detail=repr(exc))

    # -- exec --------------------------------------------------------------- #
    def run_exec(self, argv: List[str]) -> Obs:
        import shutil
        prog = argv[0] if argv else ""
        where = shutil.which(prog)
        if not where:
            return Obs("run_exec", " ".join(argv), DENIED, detail="not found")
        sens = ["egress_tooling"] if prog in {"curl", "wget", "nc", "ssh", "aws"} else []
        return Obs("run_exec", " ".join(argv), OK, data=f"<{prog} at {where}>", sensitive=sens)

    # -- network ------------------------------------------------------------ #
    def net_connect(self, host: str, port: int) -> Obs:
        try:
            with socket.create_connection((host, port), timeout=_TIMEOUT):
                return Obs("net_connect", f"{host}:{port}", OK, data="connected")
        except Exception as exc:
            return Obs("net_connect", f"{host}:{port}", DENIED, detail=repr(exc)[:80])

    def http_get(self, url: str) -> Obs:
        try:
            r = urllib.request.urlopen(url, timeout=_TIMEOUT)
            return Obs("http_get", url, OK, data=r.read(256).decode("utf-8", "replace"),
                       sensitive=["egress"])
        except Exception as exc:
            return Obs("http_get", url, DENIED, detail=repr(exc)[:80])

    # -- control plane ------------------------------------------------------ #
    def aws_call(self, service: str, action: str, params: dict) -> Obs:
        try:
            import boto3
            from botocore.exceptions import ClientError
        except Exception as exc:
            return Obs("aws_call", f"{service}:{action}", ERROR, detail=repr(exc))
        destructive = action in ("TerminateMicrovm", "RunMicrovm")
        if destructive and not _DESTRUCTIVE:
            return Obs("aws_call", f"{service}:{action}", REFUSED,
                       detail="DRY: set LAB_ALLOW_DESTRUCTIVE=1 to actually attempt")
        try:
            client = boto3.client(service, region_name=self.region)
            method = action[0].lower() + action[1:]
            getattr(client, method)(**params)
            return Obs("aws_call", f"{service}:{action}", OK, data="accepted",
                       sensitive=["control_plane_write"] if destructive else [],
                       escaped=destructive, detail="role PERMITTED this call")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "?")
            return Obs("aws_call", f"{service}:{action}", DENIED, detail=f"{code}")
        except Exception as exc:
            return Obs("aws_call", f"{service}:{action}", ERROR, detail=repr(exc)[:80])

    # -- lifecycle ---------------------------------------------------------- #
    def lifecycle(self, action: str, who: str) -> Obs:
        # Forward a lifecycle hook through the endpoint; 0.5.0 runtime ignores it.
        target = self.warden_url if who == "warden" else "http://127.0.0.1:8080"
        path = f"/aws/lambda-microvms/runtime/v1/{action}"
        try:
            req = urllib.request.Request(target + path, method="POST", data=b"{}")
            r = urllib.request.urlopen(req, timeout=_TIMEOUT)
            return Obs("lifecycle", f"{action}:{who}", REFUSED,
                       data=r.status, detail="hook ignored endpoint-forwarded call")
        except Exception as exc:
            return Obs("lifecycle", f"{action}:{who}", DENIED, detail=repr(exc)[:80])

    # -- persistence -------------------------------------------------------- #
    def persist_write(self, key: str, data: str) -> Obs:
        bucket = os.environ.get("LAB_PERSIST_BUCKET")
        if not bucket:
            return Obs("persist_write", key, DENIED, detail="no persist bucket configured")
        try:
            import boto3
            boto3.client("s3", region_name=self.region).put_object(
                Bucket=bucket, Key=key.split("/", 3)[-1], Body=data.encode())
            return Obs("persist_write", key, OK, data=len(data), sensitive=["persisted_payload"],
                       escaped=self.outer_token in data)
        except Exception as exc:
            return Obs("persist_write", key, DENIED, detail=repr(exc)[:80])

    # -- warden ------------------------------------------------------------- #
    def warden_get(self, path: str, token: Optional[str] = None) -> Obs:
        url = self.warden_url + path
        try:
            req = urllib.request.Request(url, headers=self._warden_headers())
            if token:
                req.add_header("X-Warden-Key", token)
            r = urllib.request.urlopen(req, timeout=_TIMEOUT)
            body = r.read(512).decode("utf-8", "replace")
            escaped = self.outer_token in body
            return Obs("warden_get", path, OK, data=body,
                       sensitive=["outer_flag"] if escaped else [], escaped=escaped,
                       detail="BOUNDARY FAILURE" if escaped else "")
        except Exception as exc:
            # 403 on /flag arrives here as an HTTPError: containment holding.
            return Obs("warden_get", path, REFUSED, detail=repr(exc)[:80])

    def egress_exfil(self, host: str, payload: str) -> Obs:
        # Never send a real flag; prove only whether a channel exists.
        return self.net_connect(host, 443)

    # -- DNS tunnelling ----------------------------------------------------- #
    def dns_query(self, name: str, payload: str = "") -> Obs:
        # Resolve a benign name; a success means the covert channel is open.
        # We never encode a real flag into the label.
        try:
            socket.getaddrinfo(name, None)
            return Obs("dns_query", name, OK, sensitive=["dns_exfil"],
                       detail="resolver answered: DNS channel is open")
        except Exception as exc:
            return Obs("dns_query", name, DENIED, detail=repr(exc)[:80])

    def introspect(self, code: str) -> Obs:
        # The interpreter can read any file the process can; model that by
        # reading an embedded path. We do NOT exec arbitrary os.system here.
        import re
        m = re.search(r"['\"](/[^'\"]+)['\"]", code)
        if m:
            r = self.read_file(m.group(1))
            return Obs("introspect", code[:48], r.status, data=r.data,
                       sensitive=(r.sensitive or []) + ["interpreter_breakout"])
        return Obs("introspect", code[:48], OK, sensitive=["interpreter_breakout"],
                   detail="interpreter available in-process")

    def manipulate(self, target: str, content: str) -> Obs:
        if target in ("log_poison", "warden_verdict", "forge_entry"):
            # Try to push a forged entry at the warden; it rejects non-chaining.
            try:
                req = urllib.request.Request(self.warden_url + "/observe",
                                             data=content.encode(), method="POST",
                                             headers=self._warden_headers({"Content-Type": "application/json"}))
                r = urllib.request.urlopen(req, timeout=_TIMEOUT)
                import json as _json
                ok = _json.loads(r.read() or b"{}").get("accepted", False)
                return Obs("manipulate", target, OK if ok else REFUSED,
                           detail="warden accepted forged entry" if ok else "warden ledger rejected forgery")
            except Exception as exc:
                return Obs("manipulate", target, REFUSED, detail=repr(exc)[:80])
        return Obs("manipulate", target, OK, sensitive=["prompt_injection_attempt"],
                   detail="injection recorded; operator is code")
