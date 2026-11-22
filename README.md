# perm-balance

English | [日本語](https://github.com/k-kudo-hub/perm-balance/blob/main/README.ja.md)

A CLI that checks the permission settings you give AI agents (Claude Code and Codex) by **balancing risk and convenience**.
It flags risky settings and prints a narrowed proposal that keeps your work flowing, ready to drop in.

## Why

> 最小権限の原則に従うと、最も小さい範囲から渡していくべきでしょう。
> しかし結局のところはリスクと利便性のバランスです。リスクが小さく利便性が大きいのであれば、それは許可すべきでしょうし、リスクが大きく利便性が小さいのであればもちろん採用すべきでありません。

(Translation: Following the principle of least privilege, we should start by granting the smallest scope. But in the end, it is a balance between risk and convenience. If the risk is small and the convenience is large, it should be allowed; if the risk is large and the convenience is small, it should of course not be adopted.)

Codex added permission profiles (beta), so you now write in `config.toml` where the agent may write and which hosts it may reach ([Codex permissions](https://developers.openai.com/codex/permissions), [Inside the Codex sandbox](https://openai.com/index/inside-the-codex-sandbox/)). Claude Code likewise takes, in `settings.json`, the commands it may run without asking and the scope of its sandbox ([Claude Code permissions](https://code.claude.com/docs/en/permissions)).
Now that you write the scope, telling a too-broad setting from a too-narrow one is up to you.

perm-balance turns the position above directly into its rules.

## Who it is for

Team leads and individual developers who have started running AI agents in their own repositories.
Before the agent runs, you see how much you have handed over and can write narrower settings yourself. It also helps when you make permission review part of code review.

## How verdicts are decided

For each setting, perm-balance rates the **risk** (the damage the setting allows) and the **convenience** (the confirmations and waiting it saves) as high, medium or low, and combines them.

| Risk \ Convenience | Low      | Medium        | High          |
| ------------------ | -------- | ------------- | ------------- |
| High               | ✖ Reject | ▲ Narrow      | ▲ Narrow      |
| Medium             | ✖ Reject | ▲ Narrow      | ▲ Narrow      |
| Low                | ✖ Reject | ✔ OK to allow | ✔ OK to allow |

- **✖ Reject**: low convenience. Removing it barely slows work, so following least privilege, it should not be granted
- **▲ Narrow**: both risk and convenience. perm-balance proposes a narrower scope that keeps the convenience (only the commands the project uses, moving from allow to ask, allowing inside the sandbox)
- **✔ OK to allow**: low risk with real convenience. Instead of telling you to remove it, perm-balance says plainly that it is fine
- **+ Consider adding**: changes that lower risk at almost no cost to convenience (denying reads of secret files, enabling the sandbox, removing settings that have no effect)

To start from the least privilege, proposals are built from the project's own files.
Only `package.json` scripts, `Makefile` targets and each language's standard build and test commands are allowed, and the network is limited to the project's package registries and its Git remote hosts.

## How it differs from existing scanners

Tools that check Claude Code and Codex settings already exist. [AgentShield](https://github.com/affaan-m/agentshield) grades findings from critical to info and gives a score, and [PermitLint](https://dev.to/nekoautomata/permitlint-audit-claude-code-and-codex-permissions-locally-43em) finds risky patterns and fails CI on high or critical findings.
Both rate settings by **severity**. AgentShield's fix replaces `Bash(*)` with `Bash(git *)` and `Bash(npm *)` ([Auto-Fix Engine in its README](https://github.com/affaan-m/agentshield)), but `Bash(git *)` still lets `git push --force` through without confirmation, so perm-balance rates it "Narrow".

perm-balance rates, in addition to severity, **what the setting is doing for you**.

- **Narrow while keeping convenience**: telling people to just remove a risky setting makes the agent stop for confirmation, and they end up granting the broad permission again. perm-balance reads the commands, hosts and write paths the project actually uses, and proposes a narrower setting that keeps the convenience
- **Say what is fine to allow**: low-risk, useful settings (such as allowing the repository's test command) are shown as "OK to allow", not as findings. It tells you what you can safely hand over, not only what to take away
- **Print a drop-in proposal**: besides advice per finding, it prints the parts of the settings that change with every proposal applied. With `--full-proposal` it prints the whole file, ready to replace

## Usage

Requires Node.js 20 or later.

```bash
# Check the current directory
npx perm-balance

# Check another project
npx perm-balance /path/to/your/project

# Or clone and build
git clone https://github.com/k-kudo-hub/perm-balance.git
cd perm-balance && npm install && npm run build
node dist/cli.js /path/to/your/project
```

```text
perm-balance [directory] [options]

  --user            Also check user-wide settings (~/.claude/settings.json, ~/.codex/config.toml)
  --file <path>     Also check this file (.toml is read as Codex, anything else as Claude Code). Repeatable
  --json            Print the result as JSON
  --no-proposal     Do not print the narrowed proposal
  --full-proposal   Print the whole proposed file, not just the parts that change
  -h, --help        Show help
```

Without a directory, it checks `.claude/settings.json`, `.claude/settings.local.json` and `.codex/config.toml` in the current directory.

The exit code is `0` with no reject or narrow findings, `1` with at least one, and `2` for invalid options or an unreadable settings file. Use it in CI to make permission review mandatory.

### Example output

```text
━━ .claude/settings.json (Claude Code, project settings)

✖ Reject  permissions.allow: "Edit(~/**)"
    Risk high          Allows writes to your whole home directory, so it can rewrite shell configs or SSH keys and run code on the next launch
    Convenience low    Work mostly writes inside the working directory, and confirming outside writes is enough
    → Remove it from allow

▲ Narrow  permissions.allow: "Bash(*)"
    Risk high          Any command runs without confirmation, including deleting files, sending data and changing permissions
    Convenience high   Never stops to confirm a command
    → Allow only the commands this project uses (scripts, builds, tests, read-only Git). To run commands without confirmation, enable the sandbox (see 'Consider adding' below)

+ Consider adding  Deny reads of secret files (.env)
    Why: Work rarely needs to read secrets, so denying them costs almost nothing

✔ OK to allow (low risk, real convenience)
    permissions.allow: "Bash(npm run test *)"

Narrowed proposal (only what changes; everything else stays. Use --full-proposal for the whole file):

    {
      "permissions": {
        "allow": ["Bash(npm run test *)", "Bash(git status *)", "Bash(git diff *)", "Bash(git log *)"],
        "deny": ["Read(**/.env)"]
      },
      "sandbox": { "enabled": true, "autoAllowBashIfSandboxed": true, ... }
    }
```

## What it checks

### Claude Code (`settings.json`)

| Setting                                                                | Verdict                                                                           |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `Bash` / `Bash(*)` (every command)                                     | Narrow: allow only the project's commands                                         |
| `rm`, `sudo`, `chmod` with any arguments (`Bash(rm *)`)                | Reject                                                                            |
| `curl`, `wget`, `ssh` with any arguments                               | Narrow: use WebFetch domains or sandbox domains instead                           |
| `python`, `node`, `npx`, `sh` with any arguments                       | Narrow: allow only the project's commands                                         |
| Any subcommand, such as `git *`                                        | Narrow                                                                            |
| `git push`, `npm publish`, `kubectl apply` (even with fixed arguments) | Narrow: move from allow to ask                                                    |
| `npm install`, `pip install` with any arguments                        | Narrow: move to ask                                                               |
| Bare `Edit` / `Write`, `Write(*)` (anywhere)                           | Narrow: use `Edit(./**)`                                                          |
| `Edit` on your whole home or the root (`Edit(~/**)`, `Edit(//**)`)     | Reject                                                                            |
| Bare `Read`, or `Read` on your whole home or the root                  | Reject (reads inside the working directory need no confirmation anyway)           |
| `Write(path)` (matches no file, so it has no effect)                   | Consider adding: remove it and write `Edit(path)`                                 |
| `WebFetch` / `WebFetch(domain:*)`                                      | Narrow: allow only the sites you read often                                       |
| `defaultMode: "bypassPermissions"` in user settings                    | Narrow: use `acceptEdits`                                                         |
| Home or root in `additionalDirectories`                                | Reject                                                                            |
| `"*"` in `sandbox.network.allowedDomains`                              | Narrow: only the domains the project uses                                         |
| Home or root in `sandbox.filesystem.allowWrite`                        | Narrow: only the tools' cache directories                                         |
| Read-only or project commands such as `git status`, `npm run test`     | OK to allow                                                                       |
| Broad Bash allows with the sandbox off                                 | Consider adding: enable the sandbox                                               |
| Secret files present but reads not denied                              | Consider adding: deny `Read(**/.env)` (samples like `.env.example` stay readable) |

### Codex (`config.toml`)

| Setting                                                                                                                                     | Verdict                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sandbox_mode = "danger-full-access"` / `default_permissions = ":danger-full-access"`                                                       | Narrow: a profile based on `:workspace` with restricted domains                                                                                                                                                                    |
| Full network access (`enabled = true` with `network_proxy` off, or `"*" = "allow"`, including one inherited through `extends`)              | Narrow: allow only the project's domains, enforced by the proxy; turn the network off if there are none                                                                                                                            |
| Legacy `[sandbox_workspace_write] network_access = true`                                                                                    | Narrow: move to a profile with restricted domains (with `[features] network_proxy` on, flagged only when its `domains` allows `"*"`, and narrowed there; the older network access is turned off if there are no candidate domains) |
| `"write"` on your whole home or the root (`"~"`, `":root"`), or home or root in `workspace_roots` of a write-capable profile                | Narrow: only the tools' cache directories                                                                                                                                                                                          |
| Home or root in legacy `writable_roots`                                                                                                     | Narrow                                                                                                                                                                                                                             |
| `dangerously_allow_all_unix_sockets = true` / `dangerously_allow_non_loopback_proxy = true` (in a profile or in `[features.network_proxy]`) | Reject                                                                                                                                                                                                                             |
| Both `default_permissions` and `sandbox_mode` (only `sandbox_mode` applies)                                                                 | Reject: compare write scope and network access, remove the broader one so the narrower one applies                                                                                                                                 |
| With `--user`, `sandbox_mode` in `~/.codex/config.toml` disabling the project's `default_permissions`                                       | Reject: if the project's profile is narrower, replace the user's `sandbox_mode` with the matching profile; otherwise remove the project's unused profile                                                                           |
| With `--user`, a project marked `trust_level = "untrusted"` in `~/.codex/config.toml`                                                       | Not checked: Codex does not load the project's `.codex/config.toml`. With no saved trust, the file is checked with a note that Codex loads it only after you trust the project                                                     |
| Secret files present but reads not denied                                                                                                   | Consider adding: `"**/.env" = "deny"` with `glob_scan_max_depth`                                                                                                                                                                   |

## Limitations

- It is a static check of how the settings are written. It does not observe what the agent actually does
- Risk and convenience are fixed values per rule and know nothing about your team. For example, in a repository that handles production credentials, even `WebFetch` should be removed, but perm-balance rates it "Narrow"
- Codex proposals are produced by re-serializing the TOML, so comments in the original file are not preserved
- Codex permission profiles are in beta. How each part of the spec is handled, and when it was last checked, is recorded in [docs/codex-permissions-check.md](docs/codex-permissions-check.md)
- Claude Code matches Bash rules as text, so narrowing them alone is not a security boundary ([Claude Code docs](https://code.claude.com/docs/en/permissions)). If you run commands without confirmation, combine it with the sandbox

## License

MIT
