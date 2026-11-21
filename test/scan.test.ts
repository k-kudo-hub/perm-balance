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
	it("プロジェクトの設定ファイルを見つけて点検し、設定案を作る", () => {
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

	it("許可してよい設定しかなければ、設定案を作らない", () => {
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

	it("includeUser のときはユーザーの設定も読み、ユーザーの設定として扱う", () => {
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

	it("指定したファイルを拡張子で見分けて読む", () => {
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

	it("読めないファイルは理由を返す", () => {
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

describe("ユーザー全体の設定", () => {
	it("プロジェクト固有のコマンドを案に入れず、その理由を添える", () => {
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
		expect(report?.findings[0]?.suggestion?.summary).toContain(
			"各プロジェクトの設定で許可する",
		);
	});
});
