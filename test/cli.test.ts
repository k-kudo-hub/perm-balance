import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/cli.js";

function makeDir(files: Record<string, string>): string {
	const root = mkdtempSync(join(tmpdir(), "perm-balance-cli-"));
	for (const [rel, content] of Object.entries(files)) {
		const full = join(root, rel);
		mkdirSync(join(full, ".."), { recursive: true });
		writeFileSync(full, content);
	}
	return root;
}

function run(argv: string[], root: string) {
	let out = "";
	let err = "";
	const code = main(argv, {
		cwd: root,
		home: makeDir({}),
		stdout: (s) => {
			out += s;
		},
		stderr: (s) => {
			err += s;
		},
	});
	return { code, out, err };
}

const RISKY = {
	"package.json": JSON.stringify({ scripts: { test: "vitest" } }),
	".claude/settings.json": JSON.stringify({
		permissions: { allow: ["Bash(*)", "Bash(rm *)", "Bash(npm run test *)"] },
	}),
	".codex/config.toml": "[permissions.dev.network]\nenabled = true\n",
};

describe("cli", () => {
	it("判定ごとに指摘を表示し、狭めた設定案を示して、終了コード 1 を返す", () => {
		const { code, out } = run([], makeDir(RISKY));
		expect(code).toBe(1);
		expect(out).toContain("採用しない");
		expect(out).toContain('permissions.allow: "Bash(rm *)"');
		expect(out).toContain("狭める");
		expect(out).toContain("許可してよい");
		expect(out).toContain("[permissions.dev.network] enabled = true");
		expect(out).toContain("狭めた設定案");
		expect(out).toContain('"Bash(npm run test *)"');
	});

	it("--no-proposal では設定案を表示しない", () => {
		const { out } = run(["--no-proposal"], makeDir(RISKY));
		expect(out).not.toContain("狭めた設定案");
	});

	it("--json では機械が読める形で出す", () => {
		const { code, out } = run(["--json"], makeDir(RISKY));
		expect(code).toBe(1);
		const report = JSON.parse(out);
		expect(report.files).toHaveLength(2);
		expect(report.summary).toEqual({
			reject: 1,
			narrow: 2,
			keep: 1,
			recommendations: 1,
		});
	});

	it("指摘がなければ終了コード 0 を返す", () => {
		const root = makeDir({
			".claude/settings.json": JSON.stringify({
				permissions: { allow: ["Bash(git status *)"] },
			}),
		});
		expect(run([], root).code).toBe(0);
	});

	it("設定ファイルがなければ、その旨を伝えて終了コード 0 を返す", () => {
		const { code, out } = run([], makeDir({}));
		expect(code).toBe(0);
		expect(out).toContain("設定ファイルが見つかりません");
	});

	it("引数のディレクトリを点検する", () => {
		const root = makeDir({
			"sub/.codex/config.toml": 'sandbox_mode = "danger-full-access"\n',
		});
		const { code, out } = run(["sub"], root);
		expect(code).toBe(1);
		expect(out).toContain("danger-full-access");
	});

	it("読めないファイルがあれば終了コード 2 を返す", () => {
		const { code, err } = run(
			[],
			makeDir({ ".claude/settings.json": "{ broken" }),
		);
		expect(code).toBe(2);
		expect(err).toContain(".claude/settings.json");
	});

	it("知らないオプションは使い方を出して終了コード 2 を返す", () => {
		const { code, err } = run(["--nope"], makeDir({}));
		expect(code).toBe(2);
		expect(err).toContain("使い方");
	});
});

describe("設定案の表示", () => {
	const WITH_HOOKS = {
		".claude/settings.json": JSON.stringify({
			permissions: { allow: ["Bash(rm *)"] },
			hooks: { Stop: [{ hooks: [{ type: "command", command: "echo done" }] }] },
		}),
		".codex/config.toml":
			'model = "gpt-5"\nsandbox_mode = "danger-full-access"\n',
	};

	it("既定では変わる部分だけを表示し、権限と関係のない設定は出さない", () => {
		const { out } = run([], makeDir(WITH_HOOKS));
		expect(out).toContain("変わる部分だけ");
		expect(out).not.toContain("echo done");
		expect(out).not.toContain('model = "gpt-5"');
		expect(out).toContain("消す設定: sandbox_mode");
	});

	it("--full-proposal ではファイル全体を表示する", () => {
		const { out } = run(["--full-proposal"], makeDir(WITH_HOOKS));
		expect(out).toContain("echo done");
		expect(out).toContain('model = "gpt-5"');
	});
});

describe("ユーザー全体の設定", () => {
	it("プロジェクト固有の値を案に入れない理由を、ファイルごとに1回だけ表示する", () => {
		const root = makeDir({});
		const home = makeDir({
			".claude/settings.json": JSON.stringify({
				permissions: { allow: ["Bash", "Bash(git:*)"] },
			}),
		});
		let out = "";
		main(["--user"], {
			cwd: root,
			home,
			stdout: (s) => (out += s),
			stderr: () => {},
		});
		expect(out.split("各プロジェクトの設定で許可する").length - 1).toBe(1);
	});
});
