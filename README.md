# luci-app-packetflow

**OpenWrt/LuCI Packet Flow Inspector & Debugger**

A read-only LuCI application that makes the effective Linux/OpenWrt packet-routing pipeline visible.

## Why

Complex OpenWrt systems may combine fw4/nftables, PBR, mwan3, WireGuard, Tailscale, OpenVPN, transparent proxies and custom VPN software. Each component can add chains, marks, policy rules and routing tables. The configuration may look correct while the effective kernel state tells a different story.

Packet Flow aims to answer one practical question:

> **Why does this packet leave through this interface?**

## Current MVP

The first version exposes live kernel state in LuCI under **Status → Packet Flow**:

- Netfilter/nftables base chains
- hook and chain priority
- IPv4/IPv6 RPDB (`ip rule`)
- all IPv4/IPv6 routing tables
- interfaces and state
- a high-level packet-flow pipeline

Data is collected from JSON-capable kernel/userland interfaces such as:

```sh
nft -j list ruleset
ip -j -4 rule show
ip -j -6 rule show
ip -j -4 route show table all
ip -j -6 route show table all
ip -j link show
```

The MVP is intentionally **read-only**.

## Planned

- Relationship graph: nft mark → RPDB rule → routing table → interface
- Conflict detection for marks, priorities and broken/missing route tables
- Packet Trace: source/destination/protocol/port → matched path
- Better attribution of rules to fw4, pbr, mwan3, VPN packages and custom components
- Flow-offload / conntrack visibility
- Exportable diagnostic snapshot

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Build

Place this package in an OpenWrt SDK/buildroot package feed, update feeds, select **LuCI → Applications → luci-app-packetflow**, then build normally.

## Safety

Packet Flow v0.x does not edit nftables, policy rules, routes or interfaces. The project first focuses on trustworthy observation and diagnostics; write operations may only be considered after the inspector is mature.

## License

MIT
