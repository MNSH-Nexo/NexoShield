#!/usr/bin/env python3
"""Verify the built installer against the modular sources.

Checks:
  1. install.sh on disk is byte-identical to a fresh build (src/ is in sync).
  2. Round-trip: every heredoc body extracted from install.sh matches its
     (substituted) module source exactly.
  3. The Cloudflare list holds 753 unique, well-formed CIDRs.
  4. No build placeholder survives in install.sh.
"""
import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build", ROOT / "tools" / "build.py")
build_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_mod)

failures = []


def check(ok, label):
    print(("  ok  " if ok else " FAIL ") + label)
    if not ok:
        failures.append(label)


built = build_mod.build()
on_disk = (ROOT / "install.sh").read_text(encoding="utf-8")
check(built == on_disk, "install.sh matches a fresh build from src/")

lines = built.split("\n")

# --- Cloudflare data -------------------------------------------------------
cf = [
    ln.strip()
    for ln in (ROOT / "src/data/cloudflare-ipv4.list").read_text().split("\n")
    if ln.strip()
]
check(len(cf) == 753, f"cloudflare-ipv4.list has 753 entries (got {len(cf)})")
check(len(set(cf)) == len(cf), "cloudflare-ipv4.list entries are unique")
check(
    all(re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", e) for e in cf),
    "cloudflare-ipv4.list entries are well-formed CIDRs",
)

# --- Round-trip extraction --------------------------------------------------
version = (ROOT / "VERSION").read_text().strip()


def expected_body(filename):
    body = build_mod.read(f"src/modules/{filename}")
    if filename == "antiddos.sh":
        body = body.replace("@@AUTOBAN_BODY@@", build_mod.read("src/modules/auto-ban.sh"))
    return body.replace("@@VERSION@@", version)


for _title, filename, delim in build_mod.MODULES:
    start = next(
        i for i, ln in enumerate(lines) if ln.endswith(f"<< '{delim}'")
    )
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == delim)
    extracted = "\n".join(lines[start + 1 : end])
    check(extracted == expected_body(filename), f"round-trip: {filename}")

check("@@" not in built, "no placeholders in install.sh")

if failures:
    sys.exit(f"\n{len(failures)} check(s) failed")
print("\nall verification checks passed")
