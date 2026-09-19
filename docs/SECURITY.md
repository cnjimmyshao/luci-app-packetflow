# Security model

Packet Flow v0.x is an administrative, read-only diagnostics UI.

## Principles

- Never mutate nftables, RPDB rules, routes, links or addresses.
- Prefer structured JSON output over parsing human-oriented command output.
- Validate all Route Trace user input before passing arguments to `ip`.
- Pass command arguments as argv; never construct shell command strings from user input.
- Treat inferred relationships as inference and kernel trace output as observation.
- Avoid exposing packet payloads or secrets.

The LuCI page requires its rpcd ACL and therefore should only be exposed through the normal authenticated LuCI administration surface.
