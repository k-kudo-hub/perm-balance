import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "smol-toml";
import { describe, expect, it } from "vitest";
import { scan } from "../src/scan.js";

function makeDir(files: Record<string, string>): string {
	const root = mkdtempSync(join(tmpdir(), "perm-balance-scan-"));
	for (const [rel, content] of Object.entries(files)) {
		const full = join(root, rel);
		mkdirSync(join(full, ".."), { recursive: true });
		writeFileSync(full, content);
	}
	return root;
}

describe("scan", () => {
	it("finds and checks project settings files and builds a proposal", () => {
		const root = makeDir({
			"package.json": JSON.stringify({ scripts: { test: "vitest" } }),
			".claude/settings.json": JSON.stringify({
				permissions: { allow: ["Bash(*)", "Bash(npm run test *)"] },
			}),
			".codex/config.toml": 'sandbox_mode = "danger-full-access"\n',
		});
		const home = makeDir({});
		const reports = scan({ root, home, includeUser: false, files: [] });
		expect(reports.map((r) => [r.file, r.agent, r.scope])).toEqual([
			[".claude/settings.json", "claude-code", "project"],
			[".codex/config.toml", "codex", "project"],
		]);

		const claude = reports[0];
		expect(claude?.findings.map((f) => f.verdict)).toEqual(["narrow", "keep"]);
		const proposed = JSON.parse(claude?.proposal ?? "{}");
		expect(proposed.permissions.allow).not.toContain("Bash(*)");
		expect(proposed.permissions.allow).toContain("Bash(npm run test *)");
		expect(proposed.sandbox.enabled).toBe(true);

		const codex = reports[1];
		expect(parse(codex?.proposal ?? "").default_permissions).toBe("project");
	});

	it("builds no proposal when all settings are acceptable", () => {
		const root = makeDir({
			".claude/settings.json": JSON.stringify({
				permissions: { allow: ["Bash(git status *)"] },
			}),
		});
		const [report] = scan({
			root,
			home: makeDir({}),
			includeUser: false,
			files: [],
		});
		expect(report?.proposal).toBeUndefined();
	});

	it("with includeUser, also reads user settings and treats them as user-scoped", () => {
		const root = makeDir({});
		const home = makeDir({
			".claude/settings.json": JSON.stringify({
				permissions: { defaultMode: "bypassPermissions" },
			}),
		});
		const reports = scan({ root, home, includeUser: true, files: [] });
		expect(reports).toHaveLength(1);
		expect(reports[0]?.scope).toBe("user");
		expect(reports[0]?.file).toBe("~/.claude/settings.json");
		expect(reports[0]?.findings[0]?.ruleId).toBe("claude/bypass-permissions");
	});

	it("reads specified files, detecting the format by extension", () => {
		const root = makeDir({
			"custom/codex.toml": "[sandbox_workspace_write]\nnetwork_access = true\n",
		});
		const reports = scan({
			root,
			home: makeDir({}),
			includeUser: false,
			files: [join(root, "custom/codex.toml")],
		});
		expect(reports[0]?.agent).toBe("codex");
		expect(reports[0]?.file).toBe("custom/codex.toml");
	});

	it("returns the reason for unreadable files", () => {
		const root = makeDir({ ".claude/settings.json": "{ broken" });
		const [report] = scan({
			root,
			home: makeDir({}),
			includeUser: false,
			files: [],
		});
		expect(report?.error).toBeDefined();
		expect(report?.findings).toEqual([]);
	});
});

describe("user-wide settings", () => {
	it("leaves project-specific commands out of the proposal and explains why", () => {
		const root = makeDir({
			"package.json": JSON.stringify({ scripts: { test: "vitest" } }),
		});
		const home = makeDir({
			".claude/settings.json": JSON.stringify({
				permissions: { allow: ["Bash(*)"] },
			}),
		});
		const [report] = scan({ root, home, includeUser: true, files: [] });
		const proposed = JSON.parse(report?.proposal ?? "{}");
		expect(proposed.permissions.allow).toEqual([
			"Bash(git status *)",
			"Bash(git diff *)",
			"Bash(git log *)",
		]);
		expect(report?.findings[0]?.suggestion?.summary).not.toContain(
			"in each project's own settings",
		);
	});
});

describe("re-checking the proposal", () => {
	it("re-checking after applying the proposal yields no reject or narrow findings", () => {
		const root = makeDir({
			"package.json": JSON.stringify({ scripts: { test: "vitest" } }),
			".env": "",
			".claude/settings.json": JSON.stringify({
				permissions: {
					allow: [
						"Bash(*)",
						"Bash(rm *)",
						"Edit",
						"Read",
						"WebFetch",
						"Bash(git push *)",
					],
				},
				sandbox: {
					network: { allowedDomains: ["*"] },
					filesystem: { allowWrite: ["~"] },
				},
			}),
			".codex/config.toml":
				'default_permissions = "dev"\n[permissions.dev.filesystem]\n"~" = "write"\n[permissions.dev.network]\nenabled = true\n',
		});
		const home = makeDir({});
		const first = scan({ root, home, includeUser: false, files: [] });
		writeFileSync(
			join(root, ".claude/settings.json"),
			first[0]?.proposal ?? "",
		);
		writeFileSync(join(root, ".codex/config.toml"), first[1]?.proposal ?? "");
		const second = scan({ root, home, includeUser: false, files: [] });
		for (const report of second) {
			expect(report.findings.filter((f) => f.verdict !== "keep")).toEqual([]);
			expect(report.recommendations).toEqual([]);
		}
	});
});
