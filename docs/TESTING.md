# Testing

## Static checks

CI validates LuCI JavaScript syntax and JSON manifests and contains a guard against accidentally adding obvious network-mutating commands to v0.x.

## Device smoke test

On a disposable/test OpenWrt device:

1. Install `nftables`, `ip-full`, `luci-base`, and `rpcd`.
2. Install the built `luci-app-packetflow` package.
3. Restart `rpcd` and reload LuCI.
4. Open **Status → Packet Flow**.
5. Confirm base chains, RPDB rules, routes and interfaces match:
   - `nft -j list ruleset`
   - `ip -j rule show`
   - `ip -j route show table all`
   - `ip -j link show`
6. Run Route Trace against a known destination and compare with `ip route get`.
7. Repeat with PBR/VPN/mwan3 enabled.

## Safety verification

Before release, verify that loading the page and running Route Trace does not change:

- `nft list ruleset`
- `ip rule show`
- `ip route show table all`

Capture before/after snapshots and diff them.

## Important limitation

Route Trace currently asks the kernel for a route lookup. It does **not** inject a packet and therefore does not claim to reproduce all nftables/conntrack/flow-offload behavior. A future live trace must label actual observations separately from inferred relationships.
