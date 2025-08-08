#!/usr/bin/env python3
import json
import subprocess
import sys
import socket
from typing import Dict, Any, List, Optional


IDENTITY_ENV_KEYS = ["OPENAI_API_KEY", "API_KEY", "OPENAI_TOKEN"]

MOCK_IDENTITY_MAP = {
    "/usr/local/bin/chatbot": {"type": "api-key", "name": "openai-key", "id": "chatbot-openai"},
}

ALLOWLISTS = {
    "chatbot-openai": {
        "domains": ["api.openai.com"],
        "ips": [],
        "block_shell": True,
    },
    "openai_api_key-present": {
        "domains": ["api.openai.com"],
        "ips": [],
        "block_shell": True,
    },
    "argv-openai": {
        "domains": ["api.openai.com"],
        "ips": [],
        "block_shell": True,
    },
}

TETRA_CMD = [
    "tetra",
    "--server-address",
    "unix:///var/run/tetragon/tetragon.sock",
    "getevents",
    "--output",
    "json",
]


def get_environ(pid: Optional[int]) -> Dict[str, str]:
    if pid is None:
        return {}
    path = f"/proc/{pid}/environ"
    try:
        with open(path, "rb") as f:
            raw = f.read().split(b"\x00")
        env = {}
        for item in raw:
            if not item:
                continue
            k, _, v = item.partition(b"=")
            env[k.decode(errors="ignore")] = v.decode(errors="ignore")
        return env
    except Exception:
        return {}


def infer_identity(proc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    pid = proc.get("pid")
    env = get_environ(pid)
    for k in IDENTITY_ENV_KEYS:
        if k in env and env[k]:
            return {"type": "env", "key": k, "present": True, "id": f"{k.lower()}-present"}

    binary = proc.get("binary")
    if binary in MOCK_IDENTITY_MAP:
        return MOCK_IDENTITY_MAP[binary]

    args = (proc.get("arguments") or "")
    if "OPENAI" in args.upper():
        return {"type": "argv", "name": "openai", "id": "argv-openai"}

    return None


def parse_sock_arg(args: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(args, list):
        return None
    if len(args) == 0:
        return None

    first_arg = args[0]
    if isinstance(first_arg, dict):
        sock_arg = first_arg.get("sock_arg") or first_arg.get("sock")
        if sock_arg:
            return {
                "saddr": sock_arg.get("saddr"),
                "daddr": sock_arg.get("daddr"),
                "sport": sock_arg.get("sport"),
                "dport": sock_arg.get("dport"),
                "family": sock_arg.get("family"),
                "protocol": sock_arg.get("protocol"),
            }
    return None


def detect(identity: Optional[Dict[str, Any]], proc: Optional[Dict[str, Any]], netinfo: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    ident_id = identity.get("id") if identity else None

    if proc and ident_id:
        binpath = (proc.get("binary") or "").lower()
        args = (proc.get("arguments") or "").lower()
        block_shell = ALLOWLISTS.get(ident_id, {}).get("block_shell", False)
        if block_shell and (
            binpath.endswith("/sh")
            or binpath.endswith("/bash")
            or " /bin/sh" in args
            or " /bin/bash" in args
        ):
            findings.append({
                "rule": "shell-exec",
                "severity": "high",
                "reason": "Identity-bound process launched a shell",
            })

    if netinfo and ident_id:
        allow = ALLOWLISTS.get(ident_id, {})
        allowed_ips = allow.get("ips", [])
        daddr = netinfo.get("daddr")
        if allowed_ips:
            if daddr not in allowed_ips:
                findings.append({
                    "rule": "egress-not-allowlisted-ip",
                    "severity": "medium",
                    "reason": f"Outbound to {daddr}:{netinfo.get('dport')} not in allowlist",
                })

    return findings


def normalize_event(obj: Dict[str, Any]) -> Dict[str, Any]:
    if "process_exec" in obj:
        pe = obj["process_exec"]
        return {
            "type": "exec",
            "process": pe.get("process", {}),
            "parent": pe.get("parent", {}),
            "time": obj.get("time"),  # top-level time
            "raw": obj,
        }
    if "process_kprobe" in obj:
        kp = obj["process_kprobe"]
        func_name = kp.get("function_name") or (kp.get("kprobe", {}) or {}).get("func") or kp.get("func")
        return {
            "type": "kprobe",
            "func": func_name,
            "process": kp.get("process", {}),
            "args": kp.get("args", []),
            "time": obj.get("time"),  # top-level time
            "raw": obj,
        }
    return {"type": "other", "raw": obj, "time": obj.get("time")}


def stream_events():
    proc = subprocess.Popen(
        TETRA_CMD,
        stdout=subprocess.PIPE,
        stderr=None,  # show errors if any on terminal
        text=True,
        bufsize=1,
    )
    if not proc.stdout:
        raise RuntimeError("Failed to open tetra getevents stdout")

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def main():
    HOSTNAME = socket.gethostname()
    for obj in stream_events():
        ev = normalize_event(obj)

        out = {
            "ts": ev.get("time"),
            "category": ev.get("type"),
            "hostname": HOSTNAME,
        }

        if ev["type"] == "exec":
            p = ev.get("process", {})
            ident = infer_identity(p)
            out.update({
                "event": "process_exec",
                "pid": p.get("pid"),
                "binary": p.get("binary"),
                "args": p.get("arguments"),
                "parent": {
                    "pid": (ev.get("parent") or {}).get("pid"),
                    "binary": (ev.get("parent") or {}).get("binary"),
                },
                "identity": ident,
            })
            findings = detect(ident, p, None)
            if findings:
                out["alerts"] = findings

        elif ev["type"] == "kprobe":
            func = (ev.get("func") or "").lower() or "unknown"
            p = ev.get("process", {})
            ident = infer_identity(p)
            netinfo = None
            if "tcp_connect" in func:
                netinfo = parse_sock_arg(ev.get("args"))
            out.update({
                "event": f"kprobe:{func}",
                "pid": p.get("pid"),
                "binary": p.get("binary"),
                "args": p.get("arguments"),
                "identity": ident,
                "network": netinfo,
            })
            findings = detect(ident, p, netinfo)
            if findings:
                out["alerts"] = findings

        else:
            out.update({"event": "other"})

        print(json.dumps(out, ensure_ascii=False))
        sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
