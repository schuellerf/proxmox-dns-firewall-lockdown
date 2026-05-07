#!/usr/bin/env python3
"""Idempotently patch a cloned CoreDNS tree: plugin.cfg + go.mod replace for this repo."""
from __future__ import annotations

import argparse
from pathlib import Path

# Historical Go module path in older clones under .build/<ver>/coredns (migrate on vendor-coredns).
LEGACY_PREFIX = "github.com/fschulle/proxmox-dns-firewall-lockdown"


def patch_plugin_cfg(path: Path, module: str) -> None:
    marker_suffix = "/plugin/pve-dns-lockdown"
    legacy_marker = "/plugin/lockdown"
    raw = (
        path.read_text()
        .replace(LEGACY_PREFIX, module)
    )
    lines = raw.splitlines()
    want = f"pve-dns-lockdown:{module}{marker_suffix}"
    out: list[str] = []
    seen_plugin = False
    for ln in lines:
        st = ln.strip()
        if st.startswith("lockdown:") and st.endswith(legacy_marker) and "proxmox-dns-firewall-lockdown" in st:
            continue  # legacy directive; re-insert before forward
        if st.startswith("pve-dns-lockdown:") and st.endswith(marker_suffix) and "proxmox-dns-firewall-lockdown" in st:
            continue  # drop to re-insert before forward
        if st.startswith("forward:") and not seen_plugin:
            out.append(want)
            seen_plugin = True
        out.append(ln)

    if not seen_plugin and want not in [x.strip() for x in out]:
        out.append(want)

    path.write_text("\n".join(out) + "\n")


def patch_go_mod(path: Path, module: str, replace_path: Path) -> None:
    text = (
        path.read_text()
        .replace(LEGACY_PREFIX, module)
    )
    want = f"replace {module} => {replace_path.resolve()}"
    lines = text.splitlines()
    out = [
        ln
        for ln in lines
        if not (ln.strip().startswith("replace ") and "proxmox-dns-firewall-lockdown" in ln)
    ]
    if want not in [x.strip() for x in out]:
        out.extend(["", want])
    path.write_text("\n".join(out) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--coredns", type=Path, required=True)
    ap.add_argument("--module", required=True)
    ap.add_argument("--replace-path", type=Path, required=True)
    args = ap.parse_args()
    patch_plugin_cfg(args.coredns / "plugin.cfg", args.module)
    patch_go_mod(args.coredns / "go.mod", args.module, args.replace_path)


if __name__ == "__main__":
    main()
