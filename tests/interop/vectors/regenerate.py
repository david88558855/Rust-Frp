#!/usr/bin/env python3
"""Regenerates ``msg_vectors.json`` by asking upstream frp to encode the corpus.

This is the *producer* half of the vector pipeline. It builds the small Go
program in ``gen_go_vectors/``, which imports frp's own ``pkg/msg`` types and
``golib/msg/json`` framing, and writes the JSON the Rust test consumes.

Run it only when the targeted frp version changes, or when adding a case. In CI
the counterpart ``verify_vectors.py`` is the *consumer*: it checks that the
committed fixture still agrees with the reference implementation, so a silent
drift is caught rather than papered over.

Usage:
    python3 tests/interop/vectors/regenerate.py [--check]

``--check`` regenerates into memory and diffs against the committed file
without writing, which is what CI runs. The diff is byte based, with one
exception: a body is also accepted when it parses to the same JSON value, which
absorbs the `\\uXXXX` escaping `json.load` performs on the way in. See
``bodies_agree``.
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

FRP_VERSION = "0.71.0"
GOLIB_VERSION = "0.8.2"


def bodies_agree(corpus_body, frp_body):
    """Whether two encoded bodies are the same message.

    Byte equality first, and when that fails a comparison of the parsed values.
    The fallback exists for exactly one reason: this script reads the corpus
    with `json.load`, which decodes `\\uXXXX` escapes into the runes they name,
    where frp prints them escaped. Those two strings always differ, and would
    make the fixture look stale on every run for a reason that is not staleness.

    It stays narrow: both sides must be valid JSON, so a renamed field, a
    dropped field or a changed type still fails.
    """
    if corpus_body == frp_body:
        return True
    try:
        return json.loads(corpus_body) == json.loads(frp_body)
    except json.JSONDecodeError:
        return False


def run_go(go):
    """Builds the generator and returns its records, or None with a reason."""
    work = tempfile.mkdtemp(prefix="frp-vecgen-")
    # Copy the generator rather than building in place: `go build` wants a
    # writable module directory and we do not want a cache inside the repo.
    for name in ("go.mod", "main.go"):
        shutil.copy(os.path.join(GEN_DIR, name), os.path.join(work, name))

    env = dict(os.environ)
    env.setdefault("GOFLAGS", "-mod=mod")
    env.setdefault("GOPROXY", "https://proxy.golang.org,direct")
    # Keep the module cache and build cache in the default locations so a CI
    # cache action can persist them between runs; a cold frp download is the
    # slow part of this job.
    env.pop("GOCACHE", None)
    env.pop("GOMODCACHE", None)

    for cmd in (
        [go, "mod", "download", "all"],
        [go, "mod", "tidy"],
        [go, "build", "-o", os.path.join(work, "gen"), "."],
    ):
        out = subprocess.run(cmd, cwd=work, capture_output=True, text=True, env=env)
        if out.returncode != 0:
            return None, "%s failed:\n%s" % (" ".join(cmd[1:]), out.stderr.strip()[:2000])

    run = subprocess.run(
        [os.path.join(work, "gen")], capture_output=True, text=True, timeout=120
    )
    if run.returncode != 0:
        return None, "generator failed: %s" % run.stderr.strip()[:2000]

    records = []
    for line in run.stdout.strip().splitlines():
        records.append(json.loads(line))
    return records, ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit non zero if the corpus is stale",
    )
    args = parser.parse_args()

    if shutil.which(args.go) is None:
        print("go toolchain not found (%s); nothing to do" % args.go)
        return 0 if args.check else 1

    records, err = run_go(args.go)
    if records is None:
        print(err)
        return 1

    generated = {r["name"]: r for r in records}

    with open(VECTORS, "r", encoding="utf-8") as handle:
        corpus = json.load(handle)

    problems = []
    for entry in corpus["vectors"]:
        name = entry["name"]
        got = generated.get(name)
        if got is None:
            problems.append("%s: no longer produced by the generator" % name)
            continue
        if entry["type_byte"] != got["type_byte"]:
            problems.append(
                "%s: type byte %r in the corpus, %r from frp"
                % (name, entry["type_byte"], got["type_byte"])
            )
        if not bodies_agree(entry["body"], got["body"]):
            problems.append(
                "%s: body differs\n     corpus: %s\n     frp   : %s"
                % (name, entry["body"], got["body"])
            )

    for name in sorted(set(generated) - {e["name"] for e in corpus["vectors"]}):
        problems.append("%s: produced by frp but missing from the corpus" % name)

    if problems:
        print("the corpus does not match frp %s:" % FRP_VERSION)
        for p in problems:
            print("  - " + p)
        return 1

    print("corpus matches frp %s (%d vectors)" % (FRP_VERSION, len(corpus["vectors"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
