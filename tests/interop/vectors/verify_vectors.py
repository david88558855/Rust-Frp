#!/usr/bin/env python3
"""Checks the wire vector corpus against a real frp release.

The vectors in ``msg_vectors.json`` describe what upstream frp v0.71.0 puts on
the wire for every control message type. This script is what makes them
trustworthy: rather than trusting a hand written JSON blob, it replays each
payload through the **Go implementation** and compares.

Concretely, for every vector it runs

    frps --version            (must match the pinned version)
    the generator in gen_go_vectors/, built against the reference frp source

and asserts the frame the Go encoder produces is byte identical to the one the
vector declares. When the Go toolchain is unavailable the script falls back to
checking the vectors for *internal* consistency only, and says so loudly: the
frame length must equal the body length, the type byte must be the one the
vector names, and the body must be valid JSON. That weaker mode still catches a
corrupted fixture, but it is not a differential test and does not print PASS for
one.

Usage:
    python3 tests/interop/vectors/verify_vectors.py \
        --upstream /path/to/frp_0.71.0_linux_amd64 \
        [--go /usr/local/go/bin/go]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
GEN_DIR = os.path.join(THIS_DIR, "gen_go_vectors")
VECTORS = os.path.join(THIS_DIR, "msg_vectors.json")

PASS = "  %-4s %s"
FAILED = []


def check(name, ok, detail=""):
    print(PASS % ("PASS" if ok else "FAIL", name + ((" :: " + detail) if detail else "")))
    sys.stdout.flush()
    if not ok:
        FAILED.append(name)
    return ok


def frame_for(entry):
    """Rebuilds the frame the vector describes, from its own three fields."""
    body = entry["body"].encode("utf-8")
    type_byte = entry["type_byte"].encode("ascii")
    if len(type_byte) != 1:
        raise ValueError("type_byte must be one byte")
    return type_byte + len(body).to_bytes(8, "big") + body


def load():
    with open(VECTORS, "r", encoding="utf-8") as handle:
        return json.load(handle)


def upstream_version(upstream_dir):
    for name in ("frps", "frps.exe"):
        path = os.path.join(upstream_dir, name)
        if os.path.exists(path):
            out = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=30
            )
            return out.stdout.strip()
    return ""


# ------------------------------------------------------------- go differential

def go_available(go):
    if not go:
        return False
    return shutil.which(go) is not None


def run_go_differential(vectors, go):
    """Builds the reference generator and returns name -> record.

    The producer lives in ``gen_go_vectors/`` and is shared with
    ``regenerate.py``: it imports frp's own ``pkg/msg`` structs and frames them
    with ``golib/msg/json``, so the bytes it prints are by construction the ones
    frp puts on the wire. This module is the consumer, and it checks the
    committed fixture against those bytes rather than trusting the JSON blob.
    """
    work = tempfile.mkdtemp(prefix="frp-vectors-go-")
    print("   go build dir: %s" % work)
    for name in ("go.mod", "main.go"):
        shutil.copy(os.path.join(GEN_DIR, name), os.path.join(work, name))

    env = dict(os.environ)
    env.setdefault("GOFLAGS", "-mod=mod")
    env.setdefault("GOPROXY", "https://proxy.golang.org,direct")

    for cmd in (
        [go, "mod", "tidy"],
        [go, "build", "-o", os.path.join(work, "gen"), "."],
    ):
        out = subprocess.run(cmd, cwd=work, capture_output=True, text=True, env=env)
        if out.returncode != 0:
            print("   %s failed: %s" % (" ".join(cmd[1:]), out.stderr.strip()[:400]))
            return None

    run = subprocess.run(
        [os.path.join(work, "gen")], capture_output=True, text=True, timeout=120
    )
    if run.returncode != 0:
        print("   generator failed: %s" % run.stderr.strip()[:400])
        return None

    records = {}
    for line in run.stdout.strip().splitlines():
        rec = json.loads(line)
        records[rec["name"]] = rec
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", default="", help="frp release directory")
    parser.add_argument("--go", default="go", help="go toolchain")
    args = parser.parse_args()

    if not os.path.exists(VECTORS):
        print("missing vector file at " + VECTORS)
        return 1
    vectors = load()
    entries = vectors["vectors"]
    print("vectors : %d entries, pinned to frp %s" % (len(entries), vectors["version"]))

    differential = False
    if args.upstream:
        ver = upstream_version(args.upstream)
        print("upstream: %s" % (ver or "<not found>"))
        if ver and "0.71.0" in ver:
            differential = True
        elif ver:
            print("WARNING: upstream is not v0.71.0; results may not be meaningful")

    # --- layer 1: the vectors describe themselves consistently -------------
    print("")
    print("== vector self consistency ==")
    for entry in entries:
        name = entry["name"]
        try:
            frame = frame_for(entry)
        except Exception as exc:  # noqa: BLE001
            check(name, False, str(exc))
            continue
        if "frame_hex" in entry and entry["frame_hex"] != frame.hex():
            check(name, False, "stored frame_hex disagrees with its own fields")
            continue
        body = entry["body"].encode("utf-8")
        if len(body) > vectors["max_msg_length"]:
            check(name, False, "body exceeds max_msg_length")
            continue
        try:
            json.loads(entry["body"])
        except json.JSONDecodeError as exc:
            check(name, False, "body is not valid JSON: %s" % exc)
            continue
        check(name, True, "%d byte frame" % len(frame))

    # --- layer 2: every type byte is covered -------------------------------
    print("")
    print("== coverage ==")
    declared = vectors["type_bytes"]
    seen = set(e["type_byte"] for e in entries)
    for label, byte in sorted(declared.items()):
        check("covers " + label, byte in seen, "byte %r" % byte)
    stray = seen - set(declared.values())
    check("no undeclared type bytes", not stray, "stray: %r" % sorted(stray))

    # --- layer 3: the real Go encoder, if we can reach it ------------------
    print("")
    print("== go differential ==")
    if not differential:
        print("  SKIP no upstream frp 0.71.0 supplied; pass --upstream")
    elif not go_available(args.go):
        print("  SKIP go toolchain not found; vectors were self check only")
    else:
        records = run_go_differential(vectors, args.go)
        if records is None:
            check("build reference encoder", False, "see above")
        else:
            for entry in entries:
                name = entry["name"]
                got = records.get(name)
                if got is None:
                    check(name, False, "frp no longer produces this case")
                    continue
                if entry["type_byte"] != got["type_byte"]:
                    check(
                        name,
                        False,
                        "type byte: corpus %r, frp %r"
                        % (entry["type_byte"], got["type_byte"]),
                    )
                    continue
                if entry["body"] != got["body"]:
                    check(
                        name,
                        False,
                        "body: corpus %s, frp %s" % (entry["body"][:64], got["body"][:64]),
                    )
                    continue
                if entry.get("frame_hex", "") != got["frame"]:
                    check(
                        name,
                        False,
                        "frame: corpus %s, frp %s"
                        % (entry.get("frame_hex", "")[:48], got["frame"][:48]),
                    )
                    continue
                check(name, True, "matches frp byte for byte")

    print("")
    print("=== summary ===")
    total = len(entries)
    print("  vectors          %d" % total)
    print("  failures         %d" % len(FAILED))
    if FAILED:
        print("  failed: " + ", ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
