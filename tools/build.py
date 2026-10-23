#!/usr/bin/env python3
"""Assemble the single-file installer (install.sh) from modular sources.

Two assembly stages:

  Stage 1 - modules. Each runtime script is assembled from small topic
  parts under src/modules/<name>/ (files starting with `# @part` headers,
  which are stripped). Lines of the form `# @include lib/<file>` are
  replaced with the body of src/lib/<file> (the part below its
  `# @lib-body` marker), so shared snippets exist exactly once.

  Stage 2 - installer. The assembled modules are embedded as heredocs
  into the installer, between src/installer/preamble.sh and outro.sh.

Substitutions: @@VERSION@@ (from the VERSION file), @@CF_ENTRIES@@
(from src/data/cloudflare-ipv4.list), @@AUTOBAN_BODY@@ (the assembled
auto-ban module, nested inside antiddos.sh). The build fails if any
placeholder or directive survives.

Usage:
    python3 tools/build.py [--output PATH]        build install.sh
    python3 tools/build.py --emit-modules DIR     write assembled modules
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

GENERATED_NOTICE = (
    "# ── GENERATED FILE ─ built by tools/build.py from src/ ─ "
    "do not edit directly; edit the sources and rebuild ──"
)

# Runtime module -> directory of its parts (assembled in filename order).
MODULE_DIRS = {
    "3proxy-socks5.sh": "3proxy",
    "optimize-sysctl.sh": "sysctl",
    "proxy-menu.sh": "menu",
    "antiddos.sh": "antiddos",
    "auto-ban.sh": "autoban",
}

# (banner title, target filename, heredoc delimiter) embedded in installer.
INSTALLER_MODULES = [
    ("File 1: 3proxy-socks5.sh", "3proxy-socks5.sh", "PROXY_SCRIPT"),
    ("File 2: optimize-sysctl.sh", "optimize-sysctl.sh", "SYSCTL_SCRIPT"),
    ("File 3: proxy-menu.sh (main menu)", "proxy-menu.sh", "MENU_SCRIPT"),
    ("File 4: antiddos.sh", "antiddos.sh", "ANTIDDOS_SCRIPT"),
]
MODULES = INSTALLER_MODULES  # backwards-compatible alias for verify.py

BANNER = "# ══════════════════════════════════════════════════════════"


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8").rstrip("\n")


def lib_body(name):
    text = read(f"src/lib/{name}")
    marker = "# @lib-body\n"
    assert marker in text, f"src/lib/{name} misses its # @lib-body marker"
    return text.split(marker, 1)[1]


def expand_includes(text):
    out = []
    for line in text.split("\n"):
        if line.startswith("# @include lib/"):
            out.append(lib_body(line.split("lib/", 1)[1].strip()))
        else:
            out.append(line)
    return "\n".join(out)


def assemble_module(filename):
    """Stage 1: parts (sorted by name) -> one module, includes expanded."""
    part_dir = ROOT / "src/modules" / MODULE_DIRS[filename]
    parts = sorted(part_dir.glob("*.sh"))
    assert parts, f"no parts found for {filename} in {part_dir}"
    chunks = []
    for part in parts:
        raw = part.read_text(encoding="utf-8")
        if raw.endswith("\n"):
            raw = raw[:-1]  # strip exactly one: trailing blank lines are content
        lines = raw.split("\n")
        # Strip the two `# @part` header lines; they are dev-only metadata.
        while lines and (
            lines[0].startswith("# @part ") or lines[0].startswith("# Assembled into")
        ):
            lines.pop(0)
        chunks.append("\n".join(lines))
    return expand_includes("\n".join(chunks))


def build():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    cf_entries = [
        line.strip()
        for line in read("src/data/cloudflare-ipv4.list").split("\n")
        if line.strip()
    ]
    cf_block = "\n".join(f'    "{entry}"' for entry in cf_entries)

    cf6_entries = [
        line.strip()
        for line in read("src/data/cloudflare-ipv6.list").split("\n")
        if line.strip()
    ]
    cf6_block = "\n".join(f'    "{entry}"' for entry in cf6_entries)

    def subst(text):
        return text.replace("@@VERSION@@", version).replace(
            "@@CF_ENTRIES@@", cf_block
        ).replace(
            "@@CF6_ENTRIES@@", cf6_block
        )

    preamble = subst(read("src/installer/preamble.sh")).split("\n")
    # Insert the generated-file notice right after the bash shebang (line 3).
    preamble.insert(3, GENERATED_NOTICE)

    parts = ["\n".join(preamble)]
    for idx, (title, filename, delim) in enumerate(INSTALLER_MODULES):
        if idx > 0:
            # Blank line(s) + banner + opener, matching the historic layout:
            # two blank lines before File 4, one before the others.
            parts.append("")
            if filename == "antiddos.sh":
                parts.append("")
            parts.append(BANNER)
            parts.append(f"# {title}")
            parts.append(BANNER)
        # BUG-025: write to a staging name; the outro verifies every
        # staged script (bash -n), backs up the previous versions and
        # only then swaps them into place - an interrupted or truncated
        # write can no longer leave a half-written live install.
        parts.append(f'cat > "$INSTALL_DIR/.{filename}.nxnew" << \'{delim}\'')
        body = assemble_module(filename)
        if filename == "antiddos.sh":
            assert "@@AUTOBAN_BODY@@" in body
            body = body.replace(
                "@@AUTOBAN_BODY@@", assemble_module("auto-ban.sh")
            )
            assert "@@NXCOUNTD_C@@" in body
            body = body.replace(
                "@@NXCOUNTD_C@@", read("src/native/nxcountd.c")
            )
        parts.append(subst(body))
        parts.append(delim)

    parts.append(subst(read("src/installer/outro.sh")))
    result = "\n".join(parts) + "\n"

    leftovers = [
        tok
        for tok in (
            "@@VERSION@@",
            "@@CF_ENTRIES@@",
            "@@CF6_ENTRIES@@",
            "@@AUTOBAN_BODY@@",
            "@@NXCOUNTD_C@@",
            "# @include",
            "# @part",
        )
        if tok in result
    ]
    if leftovers:
        sys.exit(f"build failed: unsubstituted directives: {leftovers}")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default=str(ROOT / "install.sh"))
    ap.add_argument(
        "--emit-modules",
        metavar="DIR",
        help="write the assembled runtime modules to DIR and exit",
    )
    args = ap.parse_args()
    if args.emit_modules:
        out_dir = pathlib.Path(args.emit_modules)
        out_dir.mkdir(parents=True, exist_ok=True)
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        for filename in MODULE_DIRS:
            body = assemble_module(filename)
            if filename == "antiddos.sh":
                body = body.replace(
                    "@@AUTOBAN_BODY@@", assemble_module("auto-ban.sh")
                )
                body = body.replace(
                    "@@NXCOUNTD_C@@", read("src/native/nxcountd.c")
                )
            body = body.replace("@@VERSION@@", version)
            (out_dir / filename).write_text(body + "\n", encoding="utf-8")
        print(f"modules emitted to {out_dir}")
        return
    out = pathlib.Path(args.output)
    out.write_text(build(), encoding="utf-8")
    print(f"built {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
