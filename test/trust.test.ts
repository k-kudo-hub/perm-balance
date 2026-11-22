import {
	mkdirSync,
	mkdtempSync,
	realpathSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { codexProjectTrust } from "../src/trust.js";

function makeDir(files: Record<string, string>): string {
	const root = realpathSync(mkdtempSync(join(tmpdir(), "perm-balance-trust-")));
	for (const [rel, content] of Object.entries(files)) {
		const full = join(root, rel);
		mkdirSync(join(full, ".."), { recursive: true });
		writeFileSync(full, content);
	}
	return root;
}

const projects = (entries: Record<string, string>) => ({
	projects: Object.fromEntries(
		Object.entries(entries).map(([path, level]) => [
			path,
			{ trust_level: level },
		]),
	),
});

describe("codexProjectTrust", () => {
	it("reads the trust level saved for the checked directory", () => {
		const root = makeDir({});
		expect(codexProjectTrust(projects({ [root]: "untrusted" }), root)).toEqual({
			level: "untrusted",
			key: root,
		});
		expect(codexProjectTrust(projects({ [root]: "trusted" }), root)).toEqual({
			level: "trusted",
			key: root,
		});
	});

	it("returns no level when nothing is saved, with the key Codex would ask to trust", () => {
		const root = makeDir({ ".git/HEAD": "ref: refs/heads/main\n" });
		const dir = join(root, "packages/app");
		mkdirSync(dir, { recursive: true });
		expect(codexProjectTrust({}, dir)).toEqual({ level: undefined, key: root });
		expect(codexProjectTrust(undefined, dir)).toEqual({
			level: undefined,
			key: root,
		});
	});

	it("falls back to the project root (the nearest directory with .git)", () => {
		const root = makeDir({ ".git/HEAD": "ref: refs/heads/main\n" });
		const dir = join(root, "packages/app");
		mkdirSync(dir, { recursive: true });
		expect(codexProjectTrust(projects({ [root]: "untrusted" }), dir)).toEqual({
			level: "untrusted",
			key: root,
		});
	});

	it("prefers the checked directory's own entry over the project root's", () => {
		const root = makeDir({ ".git/HEAD": "ref: refs/heads/main\n" });
		const dir = join(root, "app");
		mkdirSync(dir);
		expect(
			codexProjectTrust(
				projects({ [root]: "untrusted", [dir]: "trusted" }),
				dir,
			),
		).toEqual({ level: "trusted", key: dir });
	});

	it("uses project_root_markers from the user config to find the project root", () => {
		const root = makeDir({ "package.json": "{}" });
		const dir = join(root, "src");
		mkdirSync(dir);
		const config = {
			project_root_markers: ["package.json"],
			...projects({ [root]: "untrusted" }),
		};
		expect(codexProjectTrust(config, dir)).toEqual({
			level: "untrusted",
			key: root,
		});
		// Without the marker, package.json does not make a project root
		expect(
			codexProjectTrust(projects({ [root]: "untrusted" }), dir).level,
		).toBeUndefined();
	});

	it("falls back to the main checkout for a linked git worktree", () => {
		const main = makeDir({ ".git/HEAD": "ref: refs/heads/main\n" });
		const wt = makeDir({});
		const gitDir = join(main, ".git/worktrees/wt");
		mkdirSync(gitDir, { recursive: true });
		writeFileSync(join(gitDir, "HEAD"), "ref: refs/heads/wt\n");
		writeFileSync(join(gitDir, "commondir"), "../..\n");
		writeFileSync(join(gitDir, "gitdir"), `${join(wt, ".git")}\n`);
		writeFileSync(join(wt, ".git"), `gitdir: ${gitDir}\n`);
		expect(codexProjectTrust(projects({ [main]: "untrusted" }), wt)).toEqual({
			level: "untrusted",
			key: main,
		});
		expect(codexProjectTrust({}, wt)).toEqual({ level: undefined, key: main });
	});

	it("matches a symlinked directory by its real path", () => {
		const real = makeDir({});
		const parent = makeDir({});
		const link = join(parent, "link");
		symlinkSync(real, link);
		expect(codexProjectTrust(projects({ [real]: "untrusted" }), link)).toEqual({
			level: "untrusted",
			key: real,
		});
		expect(codexProjectTrust(projects({ [link]: "untrusted" }), link)).toEqual({
			level: "untrusted",
			key: link,
		});
	});

	it("ignores entries without a known trust level", () => {
		const root = makeDir({});
		expect(
			codexProjectTrust(
				{ projects: { [root]: { trust_level: "maybe" } } },
				root,
			).level,
		).toBeUndefined();
		expect(
			codexProjectTrust({ projects: { [root]: "trusted" } }, root).level,
		).toBeUndefined();
	});
});
