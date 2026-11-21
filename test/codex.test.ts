import { parse } from "smol-toml";
import { describe, expect, it } from "vitest";
import { applyPatches } from "../src/patch.js";
import type { ProjectFacts } from "../src/project.js";
import { checkCodexConfig } from "../src/rules/codex.js";

const facts: ProjectFacts = {
	root: "/repo",
	languages: ["node"],
	packageManager: "npm",
	scripts: ["test"],
	makeTargets: [],
	pythonTools: [],
	secretFiles: [],
	gitHosts: ["github.com"],
};

function check(toml: string, overrides: Partial<ProjectFacts> = {}) {
	const config = parse(toml);
	const result = checkCodexConfig(config, {
		file: ".codex/config.toml",
		scope: "project",
		facts: { ...facts, ...overrides },
	});
	return { config, ...result };
}

function proposal(toml: string, overrides: Partial<ProjectFacts> = {}) {
	const { config, findings, recommendations } = check(toml, overrides);
	const patches = [
		...findings.flatMap((f) => f.suggestion?.patches ?? []),
		...recommendations.flatMap((r) => r.patches),
	];
	return applyPatches(config, patches);
}

const NARROW_PROFILE = {
	extends: ":workspace",
	network: {
		enabled: true,
		domains: { "registry.npmjs.org": "allow", "github.com": "allow" },
	},
};

describe("サンドボックスなし", () => {
	it("sandbox_mode の danger-full-access は、ワークスペースだけ書けて宛先を絞ったプロファイルに狭める", () => {
		const toml =
			'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n';
		const { findings } = check(toml);
		expect(findings[0]?.ruleId).toBe("codex/danger-full-access");
		expect(findings[0]?.verdict).toBe("narrow");
		expect(findings[0]?.riskReason).toContain("approval_policy");
		expect(proposal(toml)).toEqual({
			approval_policy: "never",
			default_permissions: "project",
			features: { network_proxy: true },
			permissions: { project: NARROW_PROFILE },
		});
	});

	it("default_permissions の :danger-full-access も同じに扱う", () => {
		const { findings } = check('default_permissions = ":danger-full-access"\n');
		expect(findings[0]?.ruleId).toBe("codex/danger-full-access");
	});

	it("名前が重なるときは別の名前のプロファイルを作る", () => {
		const toml =
			'default_permissions = ":danger-full-access"\n[permissions.project]\nextends = ":read-only"\n';
		expect(proposal(toml).default_permissions).toBe("project-narrow");
	});
});

describe("ネットワークの全許可", () => {
	it("宛先を決めずにネットワークを有効にしたプロファイルは、宛先を絞る", () => {
		const toml =
			'default_permissions = "dev"\n[permissions.dev]\nextends = ":workspace"\n[permissions.dev.network]\nenabled = true\n';
		const { findings } = check(toml);
		expect(findings[0]?.ruleId).toBe("codex/network-all");
		expect(findings[0]?.verdict).toBe("narrow");
		expect(proposal(toml)).toEqual({
			default_permissions: "dev",
			features: { network_proxy: true },
			permissions: { dev: NARROW_PROFILE },
		});
	});

	it('"*" = "allow" はすべての宛先の許可として扱う', () => {
		const toml =
			'[features]\nnetwork_proxy = true\n[permissions.dev.network]\nenabled = true\n[permissions.dev.network.domains]\n"*" = "allow"\n';
		const p = proposal(toml) as {
			permissions: { dev: { network: { domains: Record<string, string> } } };
		};
		expect(p.permissions.dev.network.domains).toEqual({
			"registry.npmjs.org": "allow",
			"github.com": "allow",
		});
	});

	it("ドメインを絞っていても、プロキシが無効なら全許可として扱う", () => {
		const toml =
			'[permissions.dev.network]\nenabled = true\n[permissions.dev.network.domains]\n"api.openai.com" = "allow"\n';
		const { findings } = check(toml);
		expect(findings[0]?.riskReason).toContain("network_proxy");
		const p = proposal(toml) as {
			features: unknown;
			permissions: { dev: { network: { domains: unknown } } };
		};
		expect(p.features).toEqual({ network_proxy: true });
		expect(p.permissions.dev.network.domains).toEqual({
			"api.openai.com": "allow",
		});
	});

	it("ドメインを絞ってプロキシも有効なら指摘しない", () => {
		const toml =
			'[features]\nnetwork_proxy = true\n[permissions.dev.network]\nenabled = true\n[permissions.dev.network.domains]\n"api.openai.com" = "allow"\n';
		expect(check(toml).findings).toEqual([]);
	});

	it("旧来の network_access = true は、宛先を絞ったプロファイルに移す", () => {
		const toml =
			'sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nnetwork_access = true\nwritable_roots = ["/tmp/build"]\n';
		const { findings } = check(toml);
		expect(findings[0]?.ruleId).toBe("codex/legacy-network-all");
		expect(proposal(toml)).toEqual({
			default_permissions: "project",
			features: { network_proxy: true },
			permissions: {
				project: { ...NARROW_PROFILE, filesystem: { "/tmp/build": "write" } },
			},
		});
	});
});

describe("ホーム全体・ルート全体への書き込み", () => {
	it("プロファイルの ~ への書き込みは、キャッシュの場所に狭める", () => {
		const toml = '[permissions.dev.filesystem]\n"~" = "write"\n';
		const { findings } = check(toml);
		expect(findings[0]?.ruleId).toBe("codex/write-home");
		expect(findings[0]?.verdict).toBe("narrow");
		expect(proposal(toml)).toEqual({
			permissions: { dev: { filesystem: { "~/.npm": "write" } } },
		});
	});

	it(":root への書き込みも指摘する", () => {
		expect(
			check('[permissions.dev.filesystem]\n":root" = "write"\n').findings[0]
				?.ruleId,
		).toBe("codex/write-home");
		expect(
			check('[permissions.dev.filesystem.":root"]\n"." = "write"\n').findings[0]
				?.ruleId,
		).toBe("codex/write-home");
	});

	it("読み取りだけなら指摘しない", () => {
		expect(
			check('[permissions.dev.filesystem]\n":root" = "read"\n').findings,
		).toEqual([]);
	});

	it("旧来の writable_roots のホームも指摘する", () => {
		const toml =
			'sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nwritable_roots = ["~"]\n';
		expect(check(toml).findings[0]?.ruleId).toBe("codex/legacy-write-home");
	});
});

describe("そのほか", () => {
	it("すべての Unix ソケットの許可は採用しない", () => {
		const toml =
			"[permissions.dev.network]\ndangerously_allow_all_unix_sockets = true\n";
		const f = check(toml).findings.find(
			(x) => x.ruleId === "codex/all-unix-sockets",
		);
		expect(f?.verdict).toBe("reject");
	});

	it("default_permissions と sandbox_mode を両方書くと、プロファイルが効かないことを指摘する", () => {
		const toml =
			'default_permissions = "dev"\nsandbox_mode = "workspace-write"\n';
		const f = check(toml).findings.find(
			(x) => x.ruleId === "codex/profile-ignored",
		);
		expect(f?.verdict).toBe("reject");
	});

	it("標準の :workspace だけなら指摘しない", () => {
		expect(check('default_permissions = ":workspace"\n').findings).toEqual([]);
	});
});

describe("足すとよい設定", () => {
	it("秘密情報のファイルがあれば、プロファイルで読み取りを拒否する", () => {
		const toml = 'default_permissions = ":workspace"\n';
		expect(proposal(toml, { secretFiles: [".env"] })).toEqual({
			default_permissions: "project",
			permissions: {
				project: {
					extends: ":workspace",
					filesystem: { ":workspace_roots": { "**/.env": "deny" } },
				},
			},
		});
	});

	it("使っているプロファイルに足す", () => {
		const toml =
			'default_permissions = "dev"\n[permissions.dev]\nextends = ":workspace"\n';
		const p = proposal(toml, { secretFiles: [".env"] }) as {
			permissions: Record<string, unknown>;
		};
		expect(p.permissions).toEqual({
			dev: {
				extends: ":workspace",
				filesystem: { ":workspace_roots": { "**/.env": "deny" } },
			},
		});
	});

	it("すでに拒否していれば勧めない", () => {
		const toml =
			'default_permissions = "dev"\n[permissions.dev.filesystem.":workspace_roots"]\n"**/.env" = "deny"\n';
		expect(check(toml, { secretFiles: [".env"] }).recommendations).toEqual([]);
	});

	it("旧来の sandbox_mode を使っているときはプロファイルが効かないので勧めない", () => {
		const toml = 'sandbox_mode = "workspace-write"\n';
		expect(check(toml, { secretFiles: [".env"] }).recommendations).toEqual([]);
	});
});
