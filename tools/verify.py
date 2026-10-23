#!/usr/bin/env python3
"""Verify the built installer against the modular sources.

Checks:
  1. install.sh on disk is byte-identical to a fresh build (src/ is in sync).
  2. Round-trip: every heredoc body extracted from install.sh matches its
     assembled module source exactly.
  3. The Cloudflare list holds 753 unique, well-formed CIDRs.
  4. No build placeholder or directive survives in install.sh.
  5. De-duplication: the Cloudflare loader body exists in exactly ONE
     source file (src/lib/), and no module part contains a private copy.
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
    body = build_mod.assemble_module(filename)
    if filename == "antiddos.sh":
        body = body.replace(
            "@@AUTOBAN_BODY@@", build_mod.assemble_module("auto-ban.sh")
        )
        body = body.replace(
            "@@NXCOUNTD_C@@", build_mod.read("src/native/nxcountd.c")
        )
    return body.replace("@@VERSION@@", version)


for _title, filename, delim in build_mod.INSTALLER_MODULES:
    start = next(
        i for i, ln in enumerate(lines) if ln.endswith(f"<< '{delim}'")
    )
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == delim)
    extracted = "\n".join(lines[start + 1 : end])
    check(extracted == expected_body(filename), f"round-trip: {filename}")

check("@@" not in built, "no placeholders in install.sh")
check(
    "# @include" not in built and "# @part" not in built,
    "no build directives in install.sh",
)

# --- De-duplication ----------------------------------------------------------
needle = "while IFS= read -r _cfl; do"
holders = [
    str(p.relative_to(ROOT))
    for p in (ROOT / "src").rglob("*.sh")
    if needle in p.read_text(encoding="utf-8")
]
check(
    holders == ["src/lib/cloudflare-loader.sh"],
    f"cloudflare loader exists only in src/lib (found: {holders})",
)

if failures:
    sys.exit(f"\n{len(failures)} check(s) failed")
print("\nall verification checks passed")
