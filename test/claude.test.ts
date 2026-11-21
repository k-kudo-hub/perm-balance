import { homedir } from "node:os";
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

describe("Bash allow rules", () => {
	it("narrows allow-all commands to the project's commands", () => {
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

	it("treats bare Bash and a trailing :* the same", () => {
		expect(verdictOf({ permissions: { allow: ["Bash"] } }, '"Bash"')).toBe(
			"narrow",
		);
		expect(verdictOf({ permissions: { allow: ["Bash(rm:*)"] } }, "rm:*")).toBe(
			"reject",
		);
	});

	it("rejects allowing destructive or privilege-escalating commands", () => {
		expect(verdictOf({ permissions: { allow: ["Bash(rm *)"] } }, "rm *")).toBe(
			"reject",
		);
		expect(
			verdictOf({ permissions: { allow: ["Bash(sudo *)"] } }, "sudo *"),
		).toBe("reject");
	});

	it("narrows commands that can run arbitrary code", () => {
		expect(
			verdictOf({ permissions: { allow: ["Bash(python3 *)"] } }, "python3 *"),
		).toBe("narrow");
		expect(
			verdictOf({ permissions: { allow: ["Bash(npx *)"] } }, "npx *"),
		).toBe("narrow");
	});

	it("narrows tools allowed without restricting subcommands", () => {
		expect(
			verdictOf({ permissions: { allow: ["Bash(git *)"] } }, "git *"),
		).toBe("narrow");
	});

	it("moves operations with external effects from allow to ask", () => {
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

	it("allows low-risk, high-convenience commands", () => {
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

	it("does not flag commands with fixed arguments", () => {
		expect(
			check({ permissions: { allow: ["Bash(rm -rf dist)"] } }).findings,
		).toEqual([]);
	});
});

describe("file and network allow rules", () => {
	it("rejects write access to the whole home directory", () => {
		expect(
			verdictOf({ permissions: { allow: ["Edit(~/**)"] } }, "Edit(~/**)"),
		).toBe("reject");
		expect(
			verdictOf({ permissions: { allow: ["Edit(//**)"] } }, "Edit(//**)"),
		).toBe("reject");
	});

	it("narrows unrestricted Edit to the working directory", () => {
		const { findings } = check({ permissions: { allow: ["Edit"] } });
		expect(findings[0]?.verdict).toBe("narrow");
		expect(findings[0]?.suggestion?.patches).toContainEqual({
			op: "add-to-array",
			path: ["permissions", "allow"],
			values: ["Edit(./**)"],
		});
	});

	it("rejects unrestricted Read (the working directory is already readable without prompts)", () => {
		const { findings } = check({ permissions: { allow: ["Read"] } });
		expect(findings[0]?.ruleId).toBe("claude/read-anywhere");
		expect(findings[0]?.verdict).toBe("reject");
	});

	it("rejects read access to the whole home directory", () => {
		expect(
			verdictOf({ permissions: { allow: ["Read(~/**)"] } }, "Read(~/**)"),
		).toBe("reject");
	});

	it("narrows WebFetch allowed for all domains", () => {
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

	it("narrows sandbox allow-all network access to the project's domains", () => {
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

	it("narrows sandbox write access to the whole home directory to cache locations", () => {
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

	it("rejects home or root as an additional working directory", () => {
		expect(
			verdictOf({ permissions: { additionalDirectories: ["~/"] } }, "~/"),
		).toBe("reject");
	});
});

describe("mode", () => {
	it("narrows bypassPermissions in user settings to acceptEdits", () => {
		const { findings } = check(
			{ permissions: { defaultMode: "bypassPermissions" } },
			"user",
		);
		expect(findings[0]?.verdict).toBe("narrow");
		expect(findings[0]?.suggestion?.patches).toEqual([
			{ op: "set", path: ["permissions", "defaultMode"], value: "acceptEdits" },
		]);
	});

	it("does not flag bypassPermissions in project settings because it has no effect", () => {
		expect(
			check({ permissions: { defaultMode: "bypassPermissions" } }).findings,
		).toEqual([]);
	});
});

describe("recommended additions", () => {
	it("recommends the sandbox when broad Bash access is allowed and the sandbox is disabled", () => {
		const { recommendations } = check({ permissions: { allow: ["Bash(*)"] } });
		const r = recommendations.find((x) => x.ruleId === "claude/enable-sandbox");
		expect(r?.patches).toContainEqual({
			op: "set",
			path: ["sandbox", "enabled"],
			value: true,
		});
	});

	it("does not recommend it when the sandbox is enabled", () => {
		const { recommendations } = check({
			permissions: { allow: ["Bash(*)"] },
			sandbox: { enabled: true },
		});
		expect(
			recommendations.find((x) => x.ruleId === "claude/enable-sandbox"),
		).toBeUndefined();
	});

	it("recommends deny rules when secret files exist and are not denied", () => {
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

	it("does not recommend when already denied", () => {
		const { recommendations } = check({
			permissions: { deny: ["Read(**/.env)"] },
		});
		expect(
			recommendations.find((x) => x.ruleId === "claude/deny-secrets"),
		).toBeUndefined();
	});
});

describe("path syntax", () => {
	it("does not treat paths starting with / as root or home, since they are relative to the settings file", () => {
		expect(check({ permissions: { allow: ["Edit(/**)"] } }).findings).toEqual(
			[],
		);
		expect(
			check({ permissions: { allow: [`Edit(${homedir()}/**)`] } }).findings,
		).toEqual([]);
	});

	it("rejects paths starting with // that point to home, since they are absolute", () => {
		expect(
			verdictOf(
				{ permissions: { allow: [`Edit(/${homedir()}/**)`] } },
				"Edit(",
			),
		).toBe("reject");
	});

	it("does not flag Edit(**) since it stays within the working directory", () => {
		expect(
			check({ permissions: { allow: ["Edit(**)", "Read(**)"] } }).findings,
		).toEqual([]);
	});

	it("treats / as root in sandbox allowWrite", () => {
		const { findings } = check({
			sandbox: { enabled: true, filesystem: { allowWrite: ["/"] } },
		});
		expect(findings[0]?.ruleId).toBe("claude/sandbox-write-home");
	});
});

describe("ineffective rules and fixed arguments", () => {
	it("recommends removing Write(path) as ineffective instead of flagging it as dangerous", () => {
		const { findings, recommendations } = check({
			permissions: { allow: ["Write(~/**)"] },
		});
		expect(findings).toEqual([]);
		expect(
			recommendations.find((r) => r.ruleId === "claude/write-path-ineffective")
				?.patches,
		).toEqual([
			{
				op: "remove-from-array",
				path: ["permissions", "allow"],
				values: ["Write(~/**)"],
			},
		]);
	});

	it("moves operations with external effects to ask even with fixed arguments", () => {
		expect(
			verdictOf({ permissions: { allow: ["Bash(git push)"] } }, "git push"),
		).toBe("narrow");
	});
});

describe("Write(*)", () => {
	it("narrows it as unrestricted write, like bare Write", () => {
		const { findings, recommendations } = check({
			permissions: { allow: ["Write(*)"] },
		});
		expect(findings[0]?.ruleId).toBe("claude/edit-anywhere");
		expect(
			recommendations.find((r) => r.ruleId === "claude/write-path-ineffective"),
		).toBeUndefined();
	});
});
