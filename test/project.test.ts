import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	allowCandidates,
	homeWriteCandidates,
	networkDomains,
	readProjectFacts,
	secretDenyGlobs,
} from "../src/project.js";

function makeProject(files: Record<string, string>): string {
	const root = mkdtempSync(join(tmpdir(), "perm-balance-"));
	for (const [rel, content] of Object.entries(files)) {
		const full = join(root, rel);
		mkdirSync(join(full, ".."), { recursive: true });
		writeFileSync(full, content);
	}
	return root;
}

describe("readProjectFacts", () => {
	it("reads the package manager from the lockfile and scripts from package.json", () => {
		const root = makeProject({
			"package.json": JSON.stringify({
				scripts: { test: "vitest", lint: "biome check ." },
			}),
			"pnpm-lock.yaml": "",
		});
		const facts = readProjectFacts(root);
		expect(facts.packageManager).toBe("pnpm");
		expect(facts.scripts).toEqual(["test", "lint"]);
		expect(facts.languages).toContain("node");
	});

	it("reads Makefile targets, excluding special targets and variable assignments", () => {
		const root = makeProject({
			Makefile:
				".PHONY: test\nCC := gcc\ntest:\n\tgo test ./...\nbuild: deps\n\tgo build\n",
		});
		expect(readProjectFacts(root).makeTargets).toEqual(["test", "build"]);
	});

	it("finds likely secret files, excluding example files", () => {
		const root = makeProject({
			".env": "A=1",
			".env.example": "A=",
			"config/server.pem": "",
			"node_modules/pkg/.env": "",
		});
		expect(readProjectFacts(root).secretFiles.sort()).toEqual([
			".env",
			"config/server.pem",
		]);
	});

	it("detects languages from manifests", () => {
		const root = makeProject({
			"Cargo.toml": "",
			"go.mod": "",
			"pyproject.toml": "[tool.pytest]",
		});
		expect(readProjectFacts(root).languages.sort()).toEqual([
			"go",
			"python",
			"rust",
		]);
	});
});

describe("allowCandidates", () => {
	it("builds allowable command candidates from scripts and targets", () => {
		const root = makeProject({
			"package.json": JSON.stringify({ scripts: { test: "vitest" } }),
			Makefile: "build:\n\techo\n",
		});
		expect(allowCandidates(readProjectFacts(root))).toEqual([
			"Bash(git status *)",
			"Bash(git diff *)",
			"Bash(git log *)",
			"Bash(npm run test *)",
			"Bash(make build)",
		]);
	});

	it("uses the standard build and test commands for Rust and Go", () => {
		const root = makeProject({ "Cargo.toml": "", "go.mod": "" });
		const candidates = allowCandidates(readProjectFacts(root));
		expect(candidates).toContain("Bash(cargo test *)");
		expect(candidates).toContain("Bash(go test *)");
	});
});

describe("networkDomains", () => {
	it("returns package registries for the languages used and the Git remote host", () => {
		const facts = {
			...readProjectFacts(makeProject({ "package.json": "{}" })),
			gitHosts: ["github.com"],
		};
		expect(networkDomains(facts)).toEqual(["registry.npmjs.org", "github.com"]);
	});
});

describe("homeWriteCandidates", () => {
	it("returns the default cache locations per language", () => {
		const facts = readProjectFacts(
			makeProject({ "package.json": "{}", "Cargo.toml": "" }),
		);
		expect(homeWriteCandidates(facts)).toEqual(["~/.npm", "~/.cargo"]);
	});
});

describe("secretDenyGlobs", () => {
	it("returns deny patterns, grouping keys and listing others by file name (example files stay readable)", () => {
		const facts = readProjectFacts(
			makeProject({
				".env": "",
				".env.local": "",
				".env.example": "",
				"a.key": "",
				"b.key": "",
			}),
		);
		expect(secretDenyGlobs(facts)).toEqual([
			"**/.env",
			"**/.env.local",
			"**/*.key",
		]);
	});

	it("returns empty when there are no secrets", () => {
		expect(secretDenyGlobs(readProjectFacts(makeProject({})))).toEqual([]);
	});
});
