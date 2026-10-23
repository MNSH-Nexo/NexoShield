#!/usr/bin/env python3
"""Assemble the single-file installer (install.sh) from modular sources.

Layout:
    VERSION                        single source of truth for the version
    src/installer/preamble.sh      installer head (contains @@CF_ENTRIES@@)
    src/installer/outro.sh         installer tail (permissions, final banner)
    src/modules/3proxy-socks5.sh   -> written to /opt/proxy-manager/ at install
    src/modules/optimize-sysctl.sh -> idem
    src/modules/proxy-menu.sh      -> idem
    src/modules/antiddos.sh        -> idem (contains @@AUTOBAN_BODY@@)
    src/modules/auto-ban.sh        -> nested inside antiddos.sh at install
    src/data/cloudflare-ipv4.list  Cloudflare IPv4 ranges, one per line

Placeholders substituted at build time: @@VERSION@@, @@CF_ENTRIES@@,
@@AUTOBAN_BODY@@. The build fails if any placeholder survives.

Usage:  python3 tools/build.py [--output PATH]   (default: install.sh)
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

GENERATED_NOTICE = (
    "# ── GENERATED FILE ─ built by tools/build.py from src/ ─ "
    "do not edit directly; edit the sources and rebuild ──"
)

# (banner title, target path variable, heredoc delimiter, module file)
MODULES = [
    ("File 1: 3proxy-socks5.sh", "3proxy-socks5.sh", "PROXY_SCRIPT"),
    ("File 2: optimize-sysctl.sh", "optimize-sysctl.sh", "SYSCTL_SCRIPT"),
    ("File 3: proxy-menu.sh (main menu)", "proxy-menu.sh", "MENU_SCRIPT"),
    ("File 4: antiddos.sh", "antiddos.sh", "ANTIDDOS_SCRIPT"),
]

BANNER = "# ══════════════════════════════════════════════════════════"


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8").rstrip("\n")


def build():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    cf_entries = [
        line.strip()
        for line in read("src/data/cloudflare-ipv4.list").split("\n")
        if line.strip()
    ]
    cf_block = "\n".join(f'    "{entry}"' for entry in cf_entries)

    def subst(text):
        return text.replace("@@VERSION@@", version).replace(
            "@@CF_ENTRIES@@", cf_block
        )

    preamble = subst(read("src/installer/preamble.sh")).split("\n")
    # Insert the generated-file notice right after the bash shebang (line 3).
    preamble.insert(3, GENERATED_NOTICE)

    parts = ["\n".join(preamble)]
    for idx, (title, filename, delim) in enumerate(MODULES):
        if idx > 0:
            # Blank line(s) + banner + opener, matching the historic layout:
            # two blank lines before File 4, one before the others.
            parts.append("")
            if filename == "antiddos.sh":
                parts.append("")
            parts.append(BANNER)
            parts.append(f"# {title}")
            parts.append(BANNER)
        parts.append(f'cat > "$INSTALL_DIR/{filename}" << \'{delim}\'')
        body = read(f"src/modules/{filename}")
        if filename == "antiddos.sh":
            autoban = read("src/modules/auto-ban.sh")
            assert "@@AUTOBAN_BODY@@" in body
            body = body.replace("@@AUTOBAN_BODY@@", autoban)
        parts.append(subst(body))
        parts.append(delim)

    parts.append(subst(read("src/installer/outro.sh")))
    result = "\n".join(parts) + "\n"

    leftovers = [
        tok
        for tok in ("@@VERSION@@", "@@CF_ENTRIES@@", "@@AUTOBAN_BODY@@")
        if tok in result
    ]
    if leftovers:
        sys.exit(f"build failed: unsubstituted placeholders: {leftovers}")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default=str(ROOT / "install.sh"))
    args = ap.parse_args()
    out = pathlib.Path(args.output)
    out.write_text(build(), encoding="utf-8")
    print(f"built {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
