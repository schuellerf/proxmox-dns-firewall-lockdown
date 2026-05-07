# Proxmox DNS + dynamic egress firewall

Dns resolver (CoreDNS + custom plugin) for Proxmox: a locked guest resolves names through **this** service; resolved IPs are **allowed or removed** on that guest’s **outgoing Proxmox firewall** according to a hostname allow list.

**Audience:** Humans and tooling should read [references.md](references.md) when something needs external input. Shared norms live in [principles.md](principles.md).

## Flow

1. Target VM/LXC uses this container as its DNS resolver.
2. The allow list lives in that guest’s Proxmox `description`, between `PROXMOX_DNS_LOCKDOWN_BEGIN` and `PROXMOX_DNS_LOCKDOWN_END` (optional `#` prefixes disable names). Other text in `description` is preserved.
3. On each successful DNS reply, allowed names trigger **ACCEPT egress** rules for the answer IPs; disallowed names remove **our** tagged rules for those IPs so default **DROP** outbound policy applies.
4. **Port 80** serves a minimal editor (Server-Sent Events, no polling), optional settings, and warns if outbound policy is not `DROP`.
5. This service reconciles bootstrap rules so the guest may reach **this** host on **53/udp,tcp** (and updates if our IP changes).

## Build

Requires Go (see CoreDNS upstream) and Git. From the repo root:

```bash
make build-coredns
```

Binary: `bin/pve-lockdown`. It runs CoreDNS per `Corefile` and the admin UI.

Optional environment:

- `PVE_DNS_LOCKDOWN_HTTP_ADDR` — admin UI listen address (default `:80`).
- `PVE_DNS_LOCKDOWN_CONFIG` — settings JSON path (default `/etc/pve-dns-lockdown/config.json`).
- `LOCKDOWN_SERVICE_IP` — advertised resolver IPv4 for bootstrap firewall rules.

## Configure

- **CoreDNS:** See [Corefile.example](Corefile.example).
- **Proxmox + token + firewall:** [docs/proxmox-setup.md](docs/proxmox-setup.md).
- **LXC / container layout:** [docs/lxc-install.md](docs/lxc-install.md).

## License

MIT — see [LICENSE](LICENSE).
