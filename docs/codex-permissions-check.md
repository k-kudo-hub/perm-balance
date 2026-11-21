# Codex permission profiles: spec vs. perm-balance rules

[日本語](codex-permissions-check.ja.md)

Codex permission profiles are in beta ("Permission profiles are under active development and may change"), so the rules in `src/rules/codex.ts` can drift from the spec. This page records, item by item, whether each part of the spec is handled correctly.

- Checked on: 2026-11-21
- Sources (`developers.openai.com/codex/...` redirects to `learn.chatgpt.com/docs/...`):
  - [Permissions](https://developers.openai.com/codex/permissions)
  - [Configuration Reference](https://developers.openai.com/codex/config-file/config-reference) (`default_permissions`, `permissions.*`, `features.network_proxy*`, `sandbox_mode`, `sandbox_workspace_write.*`, `approval_policy`)
  - [Advanced Configuration](https://developers.openai.com/codex/config-file/config-advanced) (config profiles)

Status:

- **OK**: the rules already match the spec
- **Fixed**: the rules did not match the spec and were fixed together with this page (each fix has a test in `test/codex.test.ts`)
- **Out of scope**: not checked, with the reason

## Selecting a profile

| Spec | Status | Notes |
| --- | --- | --- |
| `default_permissions` names a profile under `[permissions]` or a built-in (`:read-only`, `:workspace`, `:danger-full-access`) | OK | `:danger-full-access` is reported as "Narrow" |
| Profiles do not compose with `sandbox_mode` / `[sandbox_workspace_write]`; when `sandbox_mode` is set, the older settings apply instead of `default_permissions` | OK | Reported as `codex/profile-ignored`, removing the broader of the two |
| "If `sandbox_mode` appears in **any loaded config file**" | Out of scope | Each file is checked on its own. A `sandbox_mode` in `~/.codex/config.toml` that disables a project's profile is not detected |
| Config profiles are separate files (`~/.codex/<name>.config.toml`, Codex 0.134.0+) | Out of scope | Not scanned. Pass them with `--file` |
| Managed `requirements.toml` (`allowed_permission_profiles`, `[experimental_network]`) | Out of scope | Admin-managed, not the user's settings |

## `[permissions.<name>]`

| Spec | Status | Notes |
| --- | --- | --- |
| `extends` starts from `:read-only`, `:workspace` or another named profile | OK | The chain is followed to a built-in |
| `extends = ":danger-full-access"`, unknown parents and cycles are rejected | Out of scope | Codex refuses the config, so nothing runs with it |
| A profile without `extends` grants only what its `filesystem` table lists ("Missing or empty filesystem tables keep filesystem access restricted") | **Fixed** | It was treated like `:workspace`. Its write scope is now taken from its own `write` entries |
| `filesystem` entries add `write` on top of the parent | **Fixed** | When comparing a profile with `sandbox_mode`, `write` entries were ignored, so a profile writing more than the parent could be judged narrower |
| `description` | Out of scope | No effect on permissions |
| `[permissions.<name>.workspace_roots] "<path>" = true` adds the path as a workspace root, which receives the `:workspace_roots` rules (`:workspace` writes there) | **Fixed** | Making `~` or `/` a workspace root of a write-capable profile allows writes to the whole home or root. It is now reported as `codex/write-home` |

## Filesystem

| Spec | Status | Notes |
| --- | --- | --- |
| Values `read` / `write` / `deny`; more specific entries win; for the same path `deny` > `write` > `read` | OK | Only `write` is treated as granting writes |
| Nested form (`[filesystem."<path>"] "." = "write"`) | OK | |
| `:root`, `/`, `~` | OK | `write` is reported as `codex/write-home` |
| `:minimal`, `:tmpdir`, `:slash_tmp`, `:workspace_roots`, `~/path`, absolute paths | OK | Not the whole home or root, so not reported |
| Deny globs are deny-read rules; on Linux, WSL and native Windows, set `glob_scan_max_depth` when using an unbounded `**` pattern | **Fixed** | The secret-file proposal (`"**/.env" = "deny"`) now also sets `glob_scan_max_depth = 3`, the depth perm-balance scans for secret files. An existing value is kept |

## Network

| Spec | Status | Notes |
| --- | --- | --- |
| `network.enabled` (default `false`) allows network access but does not start the proxy; with the proxy off, access is direct and unrestricted | OK | Reported as `codex/network-all` |
| `features.network_proxy` is `boolean \| table`; as a table, `enabled = true` starts the proxy (default `false`) | **Fixed** | Only `network_proxy = true` was recognized, so `[features.network_proxy] enabled = true` was reported as "proxy off", and the proposal replaced the table with `true`. The table form is now recognized, and the proposal sets `enabled = true` inside the table |
| `domains` values `allow` / `deny`; `"*"` is an allow-only global wildcard; with the proxy on and no `allow` entries, external destinations are blocked | OK | `"*" = "allow"` is reported; a proxy with no `allow` entries is not |
| Rules are inherited through `extends` ("Set the parent once, then add or override only the rules that differ") | **Fixed** | Only the profile's own `domains` were read, so a child enabling the network under a parent with `"*" = "allow"` was missed |
| `dangerously_allow_all_unix_sockets` | OK / **Fixed** | Reported in `[permissions.<name>.network]`. The same key in `[features.network_proxy]` was missed and is now reported |
| `dangerously_allow_non_loopback_proxy` ("Leave unset for ordinary local development"; "can expose proxy listeners beyond localhost") | **Fixed** | Not checked before. Now reported as "Reject" in both places, like the other `dangerously_*` key |
| `unix_sockets."<path>" = "allow"` | Out of scope | The spec sanctions it for local integrations such as Docker, one path at a time |
| `allow_local_binding` | Out of scope | Needed when an allowed hostname resolves to a local or private address, and there is no narrower setting for that case. Literal `localhost` / `127.0.0.1` can be allowed in `domains` without it |
| `proxy_url`, `socks_url`, `enable_socks5`, `enable_socks5_udp`, `allow_upstream_proxy` | Out of scope | Listener settings. Binding beyond loopback requires `dangerously_allow_non_loopback_proxy`, which is reported |
| `network.mode` (`limited \| full`) | Out of scope | Listed only in the Configuration Reference, without its behavior |
| `[features.network_proxy.domains]` (feature-level domain policy) | Out of scope | How it combines with a profile's `domains` is not documented |

## Older sandbox settings

| Spec | Status | Notes |
| --- | --- | --- |
| `sandbox_mode = "danger-full-access"` | OK | Reported; `approval_policy = "never"` is mentioned in the reason |
| `[sandbox_workspace_write] network_access = true` | OK | Reported as `codex/legacy-network-all` |
| `[sandbox_workspace_write] writable_roots` | OK | Home or root reported as `codex/legacy-write-home` |
| `exclude_slash_tmp`, `exclude_tmpdir_env_var` | Out of scope | They only narrow access |
| `approval_policy` (`untrusted` unsupported, `on-failure` deprecated) | Out of scope | Not a permission scope |
