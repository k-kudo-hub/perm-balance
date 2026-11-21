import { describe, expect, it } from "vitest";
import type { ProjectFacts } from "../src/project.js";
import { checkClaudeSettings } from "../src/rules/claude.js";

const facts: ProjectFacts = {
	root: "/repo",
	languages: ["node"],
	packageManager: "npm",
	scripts: ["test"],
	makeTargets: [],
	pythonTools: [],
	secretFiles: [".env"],
	gitHosts: ["github.com"],
};

function check(settings: unknown, scope: "user" | "project" = "project") {
	return checkClaudeSettings(settings, {
		file: ".claude/settings.json",
		scope,
		facts,
	});
}

function verdictOf(
	settings: unknown,
	rule: string,
	scope: "user" | "project" = "project",
) {
	return check(settings, scope).findings.find((f) => f.setting.includes(rule))
		?.verdict;
}

describe("Bash の許可", () => {
	it("すべてのコマンドの許可は、プロジェクトのコマンドに狭める", () => {
		const { findings } = check({ permissions: { allow: ["Bash(*)"] } });
		const f = findings.find((x) => x.ruleId === "claude/bash-all");
		expect(f?.verdict).toBe("narrow");
		expect(f?.risk).toBe("high");
		expect(f?.suggestion?.patches).toContainEqual({
			op: "add-to-array",
			path: ["permissions", "allow"],
			values: [
				"Bash(git status *)",
				"Bash(git diff *)",
				"Bash(git log *)",
				"Bash(npm run test *)",
			],
		});
	});

	it("引数なしの Bash も、末尾が :* の書き方も同じに扱う", () => {
		expect(verdictOf({ permissions: { allow: ["Bash"] } }, '"Bash"')).toBe(
			"narrow",
		);
		expect(verdictOf({ permissions: { allow: ["Bash(rm:*)"] } }, "rm:*")).toBe(
			"reject",
		);
	});

	it("消す・権限を上げるコマンドの許可は採用しない", () => {
		expect(verdictOf({ permissions: { allow: ["Bash(rm *)"] } }, "rm *")).toBe(
			"reject",
		);
		expect(
			verdictOf({ permissions: { allow: ["Bash(sudo *)"] } }, "sudo *"),
		).toBe("reject");
	});

	it("任意のコードを動かせるコマンドの許可は狭める", () => {
		expect(
			verdictOf({ permissions: { allow: ["Bash(python3 *)"] } }, "python3 *"),
		).toBe("narrow");
		expect(
			verdictOf({ permissions: { allow: ["Bash(npx *)"] } }, "npx *"),
		).toBe("narrow");
	});

	it("サブコマンドを限らないツールの許可は狭める", () => {
		expect(
			verdictOf({ permissions: { allow: ["Bash(git *)"] } }, "git *"),
		).toBe("narrow");
	});

	it("外に影響する操作は、許可から確認（ask）に移す", () => {
		const { findings } = check({
			permissions: { allow: ["Bash(git push *)"] },
		});
		expect(findings[0]?.verdict).toBe("narrow");
		expect(findings[0]?.suggestion?.patches).toEqual([
			{
				op: "remove-from-array",
				path: ["permissions", "allow"],
				values: ["Bash(git push *)"],
			},
			{
				op: "add-to-array",
				path: ["permissions", "ask"],
				values: ["Bash(git push *)"],
			},
		]);
	});

	it("リスクが小さく利便性が大きいコマンドは許可してよい", () => {
		expect(
			verdictOf(
				{ permissions: { allow: ["Bash(npm run test *)"] } },
				"npm run test",
			),
		).toBe("keep");
		expect(
			verdictOf(
				{ permissions: { allow: ["Bash(git status *)"] } },
				"git status",
			),
		).toBe("keep");
	});

	it("引数を固定したコマンドは指摘しない", () => {
		expect(
			check({ permissions: { allow: ["Bash(rm -rf dist)"] } }).findings,
		).toEqual([]);
	});
});

describe("ファイルとネットワークの許可", () => {
	it("ホーム全体への書き込み許可は採用しない", () => {
		expect(
			verdictOf({ permissions: { allow: ["Edit(~/**)"] } }, "Edit(~/**)"),
		).toBe("reject");
		expect(
			verdictOf({ permissions: { allow: ["Edit(//**)"] } }, "Edit(//**)"),
		).toBe("reject");
	});

	it("場所を限らない Edit の許可は、作業ディレクトリに狭める", () => {
		const { findings } = check({ permissions: { allow: ["Edit"] } });
		expect(findings[0]?.verdict).toBe("narrow");
		expect(findings[0]?.suggestion?.patches).toContainEqual({
			op: "add-to-array",
			path: ["permissions", "allow"],
			values: ["Edit(./**)"],
		});
	});

	it("ホーム全体の読み取り許可は採用しない", () => {
		expect(
			verdictOf({ permissions: { allow: ["Read(~/**)"] } }, "Read(~/**)"),
		).toBe("reject");
	});

	it("すべてのドメインへの WebFetch の許可は狭める", () => {
		expect(
			verdictOf({ permissions: { allow: ["WebFetch"] } }, "WebFetch"),
		).toBe("narrow");
		expect(
			verdictOf({ permissions: { allow: ["WebFetch(domain:*)"] } }, "domain:*"),
		).toBe("narrow");
		expect(
			check({ permissions: { allow: ["WebFetch(domain:github.com)"] } })
				.findings,
		).toEqual([]);
	});

	it("サンドボックスのネットワーク全許可は、プロジェクトで使うドメインに狭める", () => {
		const { findings } = check({
			sandbox: { enabled: true, network: { allowedDomains: ["*"] } },
		});
		const f = findings.find((x) => x.ruleId === "claude/sandbox-network-all");
		expect(f?.verdict).toBe("narrow");
		expect(f?.suggestion?.patches).toContainEqual({
			op: "add-to-array",
			path: ["sandbox", "network", "allowedDomains"],
			values: ["registry.npmjs.org", "github.com"],
		});
	});

	it("サンドボックスのホーム全体への書き込み許可は、キャッシュの場所に狭める", () => {
		const { findings } = check({
			sandbox: { enabled: true, filesystem: { allowWrite: ["~"] } },
		});
		const f = findings.find((x) => x.ruleId === "claude/sandbox-write-home");
		expect(f?.verdict).toBe("narrow");
		expect(f?.suggestion?.patches).toContainEqual({
			op: "add-to-array",
			path: ["sandbox", "filesystem", "allowWrite"],
			values: ["~/.npm"],
		});
	});

	it("ホームやルートを追加の作業ディレクトリにするのは採用しない", () => {
		expect(
			verdictOf({ permissions: { additionalDirectories: ["~/"] } }, "~/"),
		).toBe("reject");
	});
});

describe("モード", () => {
	it("ユーザー設定の bypassPermissions は acceptEdits に狭める", () => {
		const { findings } = check(
			{ permissions: { defaultMode: "bypassPermissions" } },
			"user",
		);
		expect(findings[0]?.verdict).toBe("narrow");
		expect(findings[0]?.suggestion?.patches).toEqual([
			{ op: "set", path: ["permissions", "defaultMode"], value: "acceptEdits" },
		]);
	});

	it("プロジェクト設定の bypassPermissions は効かないので指摘しない", () => {
		expect(
			check({ permissions: { defaultMode: "bypassPermissions" } }).findings,
		).toEqual([]);
	});
});

describe("足すとよい設定", () => {
	it("広い Bash の許可があってサンドボックスが無効なら、サンドボックスを勧める", () => {
		const { recommendations } = check({ permissions: { allow: ["Bash(*)"] } });
		const r = recommendations.find((x) => x.ruleId === "claude/enable-sandbox");
		expect(r?.patches).toContainEqual({
			op: "set",
			path: ["sandbox", "enabled"],
			value: true,
		});
	});

	it("サンドボックスが有効なら勧めない", () => {
		const { recommendations } = check({
			permissions: { allow: ["Bash(*)"] },
			sandbox: { enabled: true },
		});
		expect(
			recommendations.find((x) => x.ruleId === "claude/enable-sandbox"),
		).toBeUndefined();
	});

	it("秘密情報のファイルがあって拒否の設定がなければ、拒否を勧める", () => {
		const { recommendations } = check({ permissions: { allow: [] } });
		expect(
			recommendations.find((x) => x.ruleId === "claude/deny-secrets")?.patches,
		).toEqual([
			{
				op: "add-to-array",
				path: ["permissions", "deny"],
				values: ["Read(**/.env)"],
			},
		]);
	});

	it("すでに拒否していれば勧めない", () => {
		const { recommendations } = check({
			permissions: { deny: ["Read(**/.env)"] },
		});
		expect(
			recommendations.find((x) => x.ruleId === "claude/deny-secrets"),
		).toBeUndefined();
	});
});
