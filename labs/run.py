#!/usr/bin/env python3
"""Run each template that declares a lab against its vulnerable and its patched container.

    python3 labs/run.py --plessor <path> --port <port> [template id...]

The template must find the vulnerable one and not the patched one. plessor's daemon must
be running on --port with a database it can reach. Each scan runs that one template, as
this repo holds it, and nothing else. labs/README.md says how a template declares a lab.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "plessor"
SIDES = ("vulnerable", "patched")
LAB_KEYS = {"port", "ready", "wait", *SIDES}
SIDE_KEYS = {"image", "build", "args"}
# Every container and image this makes is named with it, and only those are removed.
PREFIX = "templates-lab"


class Failed(Exception):
    """A lab that could not be run: what went wrong."""


def wrong(lab, root: Path = ROOT) -> str | None:
    """What is wrong with a template's `lab`, or None when it is one this runs."""
    if not isinstance(lab, dict):
        return "it is not a mapping"
    if unknown := sorted(set(lab) - LAB_KEYS):
        return f"it has keys this does not read: {unknown}"
    if not isinstance(lab.get("port", 80), int) or not isinstance(lab.get("wait", 120), int):
        return "port and wait are numbers"
    ready = lab.get("ready", "/")
    if not isinstance(ready, str) or not ready.startswith("/"):
        return "ready is a path, starting with /"
    for side in SIDES:
        given = lab.get(side)
        if not isinstance(given, dict):
            return f"it has no {side} container"
        if unknown := sorted(set(given) - SIDE_KEYS):
            return f"{side} has keys this does not read: {unknown}"
        if ("image" in given) == ("build" in given):
            return f"{side} gives an image or a folder to build, one of them"
        if "args" in given and ("build" not in given or not isinstance(given["args"], dict)):
            return f"{side}: args are build arguments, for a folder it builds"
        if "build" in given and not (root / str(given["build"]) / "Dockerfile").is_file():
            return f"{side}: {given['build']} has no Dockerfile"
    return None


def labs(templates: Path = TEMPLATES, root: Path = ROOT) -> list:
    """(id, lab) for each template that declares one, in the order of their files."""
    out = []
    for path in sorted(templates.rglob("*.yaml")):
        template = yaml.safe_load(path.read_text())
        lab = ((template.get("info") or {}).get("metadata") or {}).get("lab")
        if lab is None:
            continue
        if problem := wrong(lab, root):
            raise SystemExit(f"{path.relative_to(root)}: lab: {problem}")
        out.append((template["id"], lab))
    return out


def run(cmd: list, timeout: int = 900) -> str:
    """What `cmd` prints, or Failed with what it said when it fails."""
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if done.returncode != 0:
        said = (done.stderr or done.stdout).strip().splitlines()
        raise Failed(f"{' '.join(cmd[:3])} failed: {said[-1] if said else done.returncode}")
    return done.stdout


def image(side: dict, root: Path = ROOT) -> str:
    """The image for one side of a lab: pulled, or built from its folder with its args."""
    if "image" in side:
        run(["docker", "pull", "-q", side["image"]])
        return side["image"]
    args = {str(k): str(v) for k, v in (side.get("args") or {}).items()}
    tag = hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:12]
    name = f"{PREFIX}/{Path(side['build']).name}:{tag}"
    cmd = ["docker", "build", "-q", "-t", name]
    for key, value in sorted(args.items()):
        cmd += ["--build-arg", f"{key}={value}"]
    run(cmd + [str(root / side["build"])])
    return name


def start(name: str, side: dict, port: int) -> str:
    """Start one side's container as `name`, its port published on loopback; its URL."""
    run(["docker", "run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1::{port}", image(side)])
    published = run(["docker", "port", name, f"{port}/tcp"]).split()
    if not published:
        raise Failed(f"{name} published no port")
    return f"http://{published[0]}"


def up(base: str, ready: str | None, wait: int) -> None:
    """Wait until `ready` answers 200, or with no `ready` until / answers at all."""
    deadline = time.monotonic() + wait
    while True:
        try:
            with urllib.request.urlopen(base + (ready or "/"), timeout=5) as answer:
                if ready is None or answer.status == 200:
                    return
        except urllib.error.HTTPError:
            if ready is None:
                return
        except OSError:
            pass
        if time.monotonic() > deadline:
            raise Failed(f"{base}{ready or '/'} did not answer within {wait}s")
        time.sleep(2)


def found(events: str) -> set:
    """The ids of the templates a scan's events report findings for; Failed on its error."""
    ids = set()
    for line in events.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "error":
            raise Failed(f"the scan stopped: {event.get('message')}")
        data = event.get("data")
        if event.get("type") == "finding" and isinstance(data, dict) and data.get("template"):
            ids.add(data["template"])
    return ids


def scan(plessor: str, port: int, target: str, template: str) -> set:
    """Run `template` alone, from this repo, at `target`: the ids it found."""
    op = {
        "operation": "scan",
        "target": target,
        "templates_dir": str(TEMPLATES),
        "only": [template],
        "evasive": False,
        "timeout_ms": 10000,
    }
    return found(run([plessor, "--port", str(port), "--no-autostart", "exec", json.dumps(op)]))


def verdict(template: str, side: str, hit: bool) -> str | None:
    """What is wrong when a template finds a patched lab or misses a vulnerable one."""
    if side == "vulnerable" and not hit:
        return f"{template} did not find its vulnerable lab"
    if side == "patched" and hit:
        return f"{template} found its patched lab"
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--plessor", required=True, help="the plessor binary")
    ap.add_argument("--port", type=int, required=True, help="the port its daemon listens on")
    ap.add_argument("ids", nargs="*", help="only these templates")
    args = ap.parse_args()
    todo = labs()
    if missing := sorted(set(args.ids) - {tid for tid, _ in todo}):
        raise SystemExit(f"no template with a lab has the id {', '.join(missing)}")
    problems = []
    for tid, lab in todo:
        if args.ids and tid not in args.ids:
            continue
        for side in SIDES:
            name = f"{PREFIX}-{tid.lower()}-{side}"
            try:
                base = start(name, lab[side], lab.get("port", 80))
                up(base, lab.get("ready"), lab.get("wait", 120))
                hit = tid in scan(args.plessor, args.port, base, tid)
            except (Failed, subprocess.TimeoutExpired) as e:
                problems.append(f"{tid} {side}: {e}")
                print(problems[-1], flush=True)
                continue
            finally:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            print(f"{tid}: {'found' if hit else 'did not find'} the {side} lab", flush=True)
            if problem := verdict(tid, side, hit):
                problems.append(problem)
    if problems:
        print(f"\n{len(problems)} lab(s) went wrong:", *problems, sep="\n  ")
        sys.exit(1)


if __name__ == "__main__":
    main()
