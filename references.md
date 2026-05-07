# References — where to look when you need input

Use this file when documentation, configuration, or code is ambiguous. Humans and LLMs should follow it the same way (see [principles.md](principles.md)).

| Need | Open |
|------|------|
| What this software does end-to-end | [README.md](README.md), then [docs/proxmox-setup.md](docs/proxmox-setup.md), [docs/lxc-install.md](docs/lxc-install.md) |
| Proxmox API paths, firewall fields (`policy_out`, rules), privilege names | [Proxmox VE API Viewer](https://pve.proxmox.com/pve-docs/api-viewer/) for your cluster version |
| Narrow API token ACLs (`pveuser`, roles, `/vms/…` paths) | [Proxmox wiki — User Management](https://pve.proxmox.com/wiki/User_Management); same wiki for **API Tokens** |
| CoreDNS plugins, ordering, rebuilding with `plugin.cfg` | [CoreDNS manual](https://coredns.io/manual/toc/), project [Makefile](Makefile) (`build-coredns` target) |
| Allow-list on-disk format embedded in VM `description` | Markers `PROXMOX_DNS_LOCKDOWN_BEGIN` / `PROXMOX_DNS_LOCKDOWN_END` — see README and plugin code |

If repo code and Proxmox UI disagree on a field name, **trust your cluster’s API viewer** for that version.
