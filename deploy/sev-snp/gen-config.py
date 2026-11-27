#!/usr/bin/env python3
"""Render the manifest template into app-compose.json and the files /init reads.

Run inside deploy/sev-snp/Dockerfile. Everything written here ends up in the
measured initrd. app-compose.json is the document the sidecar serves; its
SHA-256 goes on the kernel command line. The .env files and the Caddyfile
are derived from the same parsed template, so the document and what /init
starts cannot drift apart without a change to this script.

Output directory:
  app-compose.json   {"docker_compose_file": <rendered template>, ...}
  vaultwarden.env    KEY=VALUE per line, from services.vaultwarden.environment
  proxy.env          from services.proxy.environment
  attest.env         the sidecar's environment (also in app-compose.json)
  Caddyfile          from configs.caddyfile.content
  logs               "console" or "null"
"""
import argparse
import hashlib
import json
import os
import re

import yaml

SAFE_VALUE = re.compile(r"^[A-Za-z0-9_./:@-]*$")
SAFE_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")


def env_file(path, env):
    lines = []
    for k in sorted(env):
        v = env[k]
        # /init splits these files on whitespace and never evaluates them.
        if not isinstance(v, str) or not SAFE_KEY.match(k) or not SAFE_VALUE.match(v):
            raise SystemExit(f"environment {k}={v!r}: only strings of [A-Za-z0-9_./:@-]")
        lines.append(f"{k}={v}\n")
    with open(path, "w") as f:
        f.write("".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--acme-host", required=True)
    ap.add_argument("--public-logs", required=True, choices=["true", "false"])
    ap.add_argument("--source-commit", required=True)
    ap.add_argument("--sidecar", required=True)
    ap.add_argument("--pin", action="append", default=[])
    a = ap.parse_args()

    text = open(a.template).read()
    text = text.replace("__DOMAIN__", a.domain).replace("__ACME_HOST__", a.acme_host)
    if "__" in text or "$" in text:
        raise SystemExit("template has an unfilled placeholder or a `$`")
    doc = yaml.safe_load(text)
    if sorted(doc["services"]) != ["proxy", "vaultwarden"]:
        raise SystemExit("/init starts exactly: vaultwarden, proxy, and the sidecar")
    users = {n: doc["services"][n]["user"] for n in doc["services"]}
    if users != {"vaultwarden": "1000:1000", "proxy": "1001:1001"}:
        raise SystemExit("/init and /etc/passwd assume uid 1000 and 1001")
    if doc["services"]["proxy"]["ports"] != ["443:443"]:
        raise SystemExit("only port 443 is served")

    sidecar_env = {
        "ATTEST_PLATFORM": "sev-snp",
        "ATTEST_SNP_BINDING": "measured-cmdline",
        "ATTEST_LISTEN": "127.0.0.1:8081",
        "ATTEST_APP_COMPOSE_PATH": "/etc/attested-vw/app-compose.json",
        "ATTEST_CERT_PATH": "/run/caddy/data/caddy/certificates/"
        f"{a.acme_host}-directory/{a.domain}/{a.domain}.crt",
    }
    pins = dict(p.split("=", 1) for p in a.pin)
    public_logs = a.public_logs == "true"
    app_compose = {
        "name": doc["name"],
        "runner": "attested-vw-initrd",
        "manifest_version": 1,
        # Service output on the serial console, which the host reads.
        "public_logs": public_logs,
        "allowed_envs": [],
        "docker_compose_file": text,
        "sidecar": {
            "source_commit": a.source_commit,
            "binary_sha256": hashlib.sha256(open(a.sidecar, "rb").read()).hexdigest(),
            "user": "0:0",
            "environment": sidecar_env,
        },
        "boot": pins,
    }
    os.makedirs(a.out, exist_ok=True)
    out = lambda n: os.path.join(a.out, n)
    # No trailing newline: the hash is over exactly these bytes.
    with open(out("app-compose.json"), "w") as f:
        f.write(json.dumps(app_compose, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    env_file(out("vaultwarden.env"), doc["services"]["vaultwarden"]["environment"])
    env_file(out("proxy.env"), doc["services"]["proxy"]["environment"])
    env_file(out("attest.env"), sidecar_env)
    with open(out("Caddyfile"), "w") as f:
        f.write(doc["configs"]["caddyfile"]["content"])
    with open(out("logs"), "w") as f:
        f.write("console\n" if public_logs else "null\n")


main()
