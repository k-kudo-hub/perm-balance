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
	it("prints findings per verdict, shows a narrowed proposal, and exits with code 1", () => {
		const { code, out } = run([], makeDir(RISKY));
		expect(code).toBe(1);
		expect(out).toContain("Reject");
		expect(out).toContain('permissions.allow: "Bash(rm *)"');
		expect(out).toContain("Narrow");
		expect(out).toContain("OK to allow");
		expect(out).toContain("[permissions.dev.network] enabled = true");
		expect(out).toContain("Narrowed proposal");
		expect(out).toContain('"Bash(npm run test *)"');
	});

	it("--no-proposal hides the proposal", () => {
		const { out } = run(["--no-proposal"], makeDir(RISKY));
		expect(out).not.toContain("Narrowed proposal");
	});

	it("--json prints machine-readable output", () => {
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

	it("exits with code 0 when there are no findings", () => {
		const root = makeDir({
			".claude/settings.json": JSON.stringify({
				permissions: { allow: ["Bash(git status *)"] },
			}),
		});
		expect(run([], root).code).toBe(0);
	});

	it("reports missing settings files and exits with code 0", () => {
		const { code, out } = run([], makeDir({}));
		expect(code).toBe(0);
		expect(out).toContain("No settings file found");
	});

	it("scans the directory given as an argument", () => {
		const root = makeDir({
			"sub/.codex/config.toml": 'sandbox_mode = "danger-full-access"\n',
		});
		const { code, out } = run(["sub"], root);
		expect(code).toBe(1);
		expect(out).toContain("danger-full-access");
	});

	it("exits with code 2 when a file cannot be read", () => {
		const { code, err } = run(
			[],
			makeDir({ ".claude/settings.json": "{ broken" }),
		);
		expect(code).toBe(2);
		expect(err).toContain(".claude/settings.json");
	});

	it("prints usage and exits with code 2 for an unknown option", () => {
		const { code, err } = run(["--nope"], makeDir({}));
		expect(code).toBe(2);
		expect(err).toContain("Usage");
	});
});

describe("proposal output", () => {
	const WITH_HOOKS = {
		".claude/settings.json": JSON.stringify({
			permissions: { allow: ["Bash(rm *)"] },
			hooks: { Stop: [{ hooks: [{ type: "command", command: "echo done" }] }] },
		}),
		".codex/config.toml":
			'model = "gpt-5"\nsandbox_mode = "danger-full-access"\n',
	};

	it("by default shows only the changes and omits settings unrelated to permissions", () => {
		const { out } = run([], makeDir(WITH_HOOKS));
		expect(out).toContain("only what changes");
		expect(out).not.toContain("echo done");
		expect(out).not.toContain('model = "gpt-5"');
		expect(out).toContain("Remove: sandbox_mode");
	});

	it("--full-proposal shows the whole file", () => {
		const { out } = run(["--full-proposal"], makeDir(WITH_HOOKS));
		expect(out).toContain("echo done");
		expect(out).toContain('model = "gpt-5"');
	});
});

describe("user-wide settings", () => {
	it("explains once per file why project-specific values are left out of the proposal", () => {
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
		expect(out.split("in each project's own settings").length - 1).toBe(1);
	});
});

describe("cli with Codex project trust", () => {
	function runWithHome(userToml: (root: string) => string) {
		const root = makeDir({
			".codex/config.toml": 'sandbox_mode = "danger-full-access"\n',
		});
		const home = makeDir({ ".codex/config.toml": userToml(root) });
		let out = "";
		const code = main(["--user"], {
			cwd: root,
			home,
			stdout: (s) => {
				out += s;
			},
			stderr: () => {},
		});
		return { code, out };
	}

	it("says an untrusted project's Codex settings are not checked, and exits with code 0", () => {
		const { code, out } = runWithHome(
			(root) => `[projects."${root}"]\ntrust_level = "untrusted"\n`,
		);
		expect(out).toContain("Not checked: Codex does not load this file");
		expect(out).not.toContain("danger-full-access");
		const projectSection = out.split("━━ ")[1] ?? "";
		expect(projectSection).not.toContain("No findings");
		expect(code).toBe(0);
	});

	it("notes that a project with no saved trust takes effect only after trusting", () => {
		const { code, out } = runWithHome(() => "");
		expect(out).toContain("Note: Codex loads this file only after you trust");
		expect(out).toContain("danger-full-access");
		expect(code).toBe(1);
	});
});
