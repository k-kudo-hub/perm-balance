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
	it("ロックファイルからパッケージマネージャーを、package.json からスクリプトを読む", () => {
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

	it("Makefile のターゲットを読み、特殊ターゲットと変数代入を除く", () => {
		const root = makeProject({
			Makefile:
				".PHONY: test\nCC := gcc\ntest:\n\tgo test ./...\nbuild: deps\n\tgo build\n",
		});
		expect(readProjectFacts(root).makeTargets).toEqual(["test", "build"]);
	});

	it("秘密情報らしいファイルを見つけ、見本のファイルは除く", () => {
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

	it("言語をマニフェストから見分ける", () => {
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
	it("スクリプトとターゲットから、許可してよいコマンドの候補を作る", () => {
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

	it("Rust と Go では標準のビルド・テストのコマンドを候補にする", () => {
		const root = makeProject({ "Cargo.toml": "", "go.mod": "" });
		const candidates = allowCandidates(readProjectFacts(root));
		expect(candidates).toContain("Bash(cargo test *)");
		expect(candidates).toContain("Bash(go test *)");
	});
});

describe("networkDomains", () => {
	it("使っている言語のパッケージレジストリと、Git のリモートのホストを返す", () => {
		const facts = {
			...readProjectFacts(makeProject({ "package.json": "{}" })),
			gitHosts: ["github.com"],
		};
		expect(networkDomains(facts)).toEqual(["registry.npmjs.org", "github.com"]);
	});
});

describe("homeWriteCandidates", () => {
	it("言語ごとの既定のキャッシュの置き場所を返す", () => {
		const facts = readProjectFacts(
			makeProject({ "package.json": "{}", "Cargo.toml": "" }),
		);
		expect(homeWriteCandidates(facts)).toEqual(["~/.npm", "~/.cargo"]);
	});
});

describe("secretDenyGlobs", () => {
	it("見つかった秘密情報の種類ごとに、拒否するパターンを返す", () => {
		const facts = readProjectFacts(
			makeProject({ ".env": "", ".env.local": "", "a.key": "" }),
		);
		expect(secretDenyGlobs(facts)).toEqual([
			"**/.env",
			"**/.env.*",
			"**/*.key",
		]);
	});

	it("秘密情報がなければ空", () => {
		expect(secretDenyGlobs(readProjectFacts(makeProject({})))).toEqual([]);
	});
});
