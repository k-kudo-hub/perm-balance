import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "smol-toml";
import { describe, expect, it } from "vitest";
import { scan } from "../src/scan.js";
import type { FileReport } from "../src/types.js";

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

describe("user-wide sandbox_mode with a project permission profile", () => {
	const USER_CODEX = ".codex/config.toml";
	const PROJECT_CODEX = ".codex/config.toml";

	function scanBoth(userToml: string, projectToml: string, extra = {}) {
		const root = makeDir({ [PROJECT_CODEX]: projectToml, ...extra });
		const home = makeDir({ [USER_CODEX]: userToml });
		const reports = scan({ root, home, includeUser: true, files: [] });
		const project = reports.find((r) => r.scope === "project");
		const user = reports.find((r) => r.scope === "user");
		return { root, home, project, user };
	}

	const ignored = (r?: FileReport) =>
		r?.findings.filter((f) => f.ruleId === "codex/profile-ignored") ?? [];

	it("flags the user's sandbox_mode when it disables a narrower project profile, and replaces it with the matching built-in profile", () => {
		const { user, project } = scanBoth(
			'sandbox_mode = "workspace-write"\n',
			'default_permissions = "proj"\n[permissions.proj]\nextends = ":read-only"\n',
		);
		const [finding] = ignored(user);
		expect(finding?.verdict).toBe("reject");
		expect(finding?.setting).toContain('sandbox_mode = "workspace-write"');
		expect(finding?.setting).toContain(".codex/config.toml");
		const proposed = parse(user?.proposal ?? "");
		expect(proposed.sandbox_mode).toBeUndefined();
		expect(proposed.default_permissions).toBe(":workspace");
		expect(ignored(project)).toEqual([]);
	});

	it("maps read-only to :read-only", () => {
		const { user } = scanBoth(
			'sandbox_mode = "read-only"\n',
			'default_permissions = ":read-only"\n',
		);
		expect(ignored(user)).toHaveLength(1);
		expect(parse(user?.proposal ?? "").default_permissions).toBe(":read-only");
	});

	it("keeps the extra writable roots of the legacy settings in a profile that does not collide with the project's profiles", () => {
		const { user } = scanBoth(
			'sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nwritable_roots = ["/opt/cache"]\n',
			'default_permissions = "project"\n[permissions.project]\nextends = ":read-only"\n',
		);
		const proposed = parse(user?.proposal ?? "") as Record<string, any>;
		expect(proposed.sandbox_mode).toBeUndefined();
		expect(proposed.sandbox_workspace_write).toBeUndefined();
		expect(proposed.default_permissions).not.toBe("project");
		const name = proposed.default_permissions as string;
		expect(proposed.permissions[name].extends).toBe(":workspace");
		expect(proposed.permissions[name].filesystem["/opt/cache"]).toBe("write");
	});

	it("keeps the user's own default_permissions when it is what applies after removing sandbox_mode", () => {
		const { user } = scanBoth(
			'sandbox_mode = "workspace-write"\ndefault_permissions = ":read-only"\n',
			'default_permissions = ":read-only"\n',
		);
		const proposed = parse(user?.proposal ?? "");
		expect(proposed.sandbox_mode).toBeUndefined();
		expect(proposed.default_permissions).toBe(":read-only");
	});

	it("flags the unused project profile instead when it is broader than the user's sandbox_mode", () => {
		const { user, project } = scanBoth(
			'sandbox_mode = "read-only"\n',
			'default_permissions = ":workspace"\n',
			{ ".env": "" },
		);
		expect(ignored(user)).toEqual([]);
		const [finding] = ignored(project);
		expect(finding?.verdict).toBe("reject");
		expect(finding?.setting).toContain("~/.codex/config.toml");
		const proposed = parse(project?.proposal ?? "");
		expect(proposed.default_permissions).toBeUndefined();
		// A profile would be ignored while the user's sandbox_mode stays, so no profile is recommended
		expect(project?.recommendations).toEqual([]);
	});

	it("does not flag the combination without --user", () => {
		const root = makeDir({
			[PROJECT_CODEX]: 'default_permissions = ":read-only"\n',
		});
		const home = makeDir({
			[USER_CODEX]: 'sandbox_mode = "workspace-write"\n',
		});
		const reports = scan({ root, home, includeUser: false, files: [] });
		expect(reports.flatMap((r) => r.findings)).toEqual([]);
	});

	it("leaves it to the single-file check when the project sets sandbox_mode itself", () => {
		const { user, project } = scanBoth(
			'sandbox_mode = "workspace-write"\n',
			'sandbox_mode = "read-only"\ndefault_permissions = ":read-only"\n',
		);
		expect(ignored(user)).toEqual([]);
		expect(ignored(project)).toHaveLength(1);
	});

	it("re-checking after applying both proposals yields no reject or narrow findings", () => {
		for (const [userToml, projectToml] of [
			[
				'sandbox_mode = "workspace-write"\n',
				'default_permissions = "proj"\n[permissions.proj]\nextends = ":workspace"\n[permissions.proj.network]\nenabled = false\n',
			],
			['sandbox_mode = "read-only"\n', 'default_permissions = ":workspace"\n'],
			[
				'sandbox_mode = "danger-full-access"\n',
				'default_permissions = ":read-only"\n',
			],
		] as const) {
			const { root, home, user, project } = scanBoth(userToml, projectToml, {
				".env": "",
			});
			if (user?.proposal) writeFileSync(join(home, USER_CODEX), user.proposal);
			if (project?.proposal)
				writeFileSync(join(root, PROJECT_CODEX), project.proposal);
			const second = scan({ root, home, includeUser: true, files: [] });
			for (const report of second) {
				expect(report.findings.filter((f) => f.verdict !== "keep")).toEqual([]);
				expect(report.recommendations).toEqual([]);
			}
		}
	});
});
