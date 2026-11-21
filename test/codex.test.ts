import { parse, stringify } from "smol-toml";
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

describe("no sandbox", () => {
	it("narrows sandbox_mode danger-full-access to a profile with workspace-only writes and restricted destinations", () => {
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

	it("treats default_permissions :danger-full-access the same way", () => {
		const { findings } = check('default_permissions = ":danger-full-access"\n');
		expect(findings[0]?.ruleId).toBe("codex/danger-full-access");
	});

	it("creates a profile with a different name on name collision", () => {
		const toml =
			'default_permissions = ":danger-full-access"\n[permissions.project]\nextends = ":read-only"\n';
		expect(proposal(toml).default_permissions).toBe("project-narrow");
	});
});

describe("allow-all network access", () => {
	it("restricts destinations for a profile that enables network without specifying them", () => {
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

	it('treats "*" = "allow" as allowing all destinations', () => {
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

	it("treats restricted domains as allow-all when the proxy is disabled", () => {
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

	it("does not flag restricted domains with the proxy enabled", () => {
		const toml =
			'[features]\nnetwork_proxy = true\n[permissions.dev.network]\nenabled = true\n[permissions.dev.network.domains]\n"api.openai.com" = "allow"\n';
		expect(check(toml).findings).toEqual([]);
	});

	it("migrates legacy network_access = true to a profile with restricted destinations", () => {
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

describe("writes to the whole home or root", () => {
	it("narrows profile writes to ~ to cache locations", () => {
		const toml = '[permissions.dev.filesystem]\n"~" = "write"\n';
		const { findings } = check(toml);
		expect(findings[0]?.ruleId).toBe("codex/write-home");
		expect(findings[0]?.verdict).toBe("narrow");
		expect(proposal(toml)).toEqual({
			permissions: { dev: { filesystem: { "~/.npm": "write" } } },
		});
	});

	it("also flags writes to :root", () => {
		expect(
			check('[permissions.dev.filesystem]\n":root" = "write"\n').findings[0]
				?.ruleId,
		).toBe("codex/write-home");
		expect(
			check('[permissions.dev.filesystem.":root"]\n"." = "write"\n').findings[0]
				?.ruleId,
		).toBe("codex/write-home");
	});

	it("does not flag read-only access", () => {
		expect(
			check('[permissions.dev.filesystem]\n":root" = "read"\n').findings,
		).toEqual([]);
	});

	it("also flags home in legacy writable_roots", () => {
		const toml =
			'sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nwritable_roots = ["~"]\n';
		expect(check(toml).findings[0]?.ruleId).toBe("codex/legacy-write-home");
	});
});

describe("other", () => {
	it("rejects allowing all Unix sockets", () => {
		const toml =
			"[permissions.dev.network]\ndangerously_allow_all_unix_sockets = true\n";
		const f = check(toml).findings.find(
			(x) => x.ruleId === "codex/all-unix-sockets",
		);
		expect(f?.verdict).toBe("reject");
	});

	it("flags that the profile has no effect when both default_permissions and sandbox_mode are set", () => {
		const toml =
			'default_permissions = "dev"\nsandbox_mode = "workspace-write"\n';
		const f = check(toml).findings.find(
			(x) => x.ruleId === "codex/profile-ignored",
		);
		expect(f?.verdict).toBe("reject");
	});

	it("does not flag the built-in :workspace alone", () => {
		expect(check('default_permissions = ":workspace"\n').findings).toEqual([]);
	});
});

describe("recommended additions", () => {
	it("denies reading secret files in the profile", () => {
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

	it("adds to the profile in use", () => {
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

	it("does not recommend when already denied", () => {
		const toml =
			'default_permissions = "dev"\n[permissions.dev.filesystem.":workspace_roots"]\n"**/.env" = "deny"\n';
		expect(check(toml, { secretFiles: [".env"] }).recommendations).toEqual([]);
	});

	it("does not recommend when legacy sandbox_mode is used, since profiles have no effect", () => {
		const toml = 'sandbox_mode = "workspace-write"\n';
		expect(check(toml, { secretFiles: [".env"] }).recommendations).toEqual([]);
	});
});

describe("both sandbox_mode and default_permissions set", () => {
	it("removes the unused default_permissions when it is broader (does not widen permissions)", () => {
		const toml =
			'sandbox_mode = "workspace-write"\ndefault_permissions = ":danger-full-access"\n';
		const { findings } = check(toml);
		expect(findings.map((f) => f.ruleId)).toEqual(["codex/profile-ignored"]);
		expect(proposal(toml)).toEqual({ sandbox_mode: "workspace-write" });
	});

	it("does not widen read-only to :workspace", () => {
		const toml =
			'sandbox_mode = "read-only"\ndefault_permissions = ":workspace"\n';
		expect(proposal(toml)).toEqual({ sandbox_mode: "read-only" });
	});

	it("removes sandbox_mode and keeps the user's profile when the profile is narrower", () => {
		const toml =
			'sandbox_mode = "danger-full-access"\ndefault_permissions = "a"\n[permissions.a]\nextends = ":read-only"\n';
		const { findings } = check(toml);
		expect(findings.map((f) => f.ruleId)).toEqual(["codex/profile-ignored"]);
		expect(proposal(toml)).toEqual({
			default_permissions: "a",
			permissions: { a: { extends: ":read-only" } },
		});
	});
});

describe("re-checking the proposal", () => {
	it("does not flag a proxy with no allowed destinations, since no outbound traffic is possible", () => {
		const toml =
			"[features]\nnetwork_proxy = true\n[permissions.dev.network]\nenabled = true\n";
		expect(check(toml).findings).toEqual([]);
	});

	it("proposes disabling network when there are no candidate destinations, and that proposal has no findings", () => {
		const toml = "[permissions.dev.network]\nenabled = true\n";
		const noDomains = {
			languages: [],
			packageManager: undefined,
			gitHosts: [],
		};
		const p = proposal(toml, noDomains);
		expect(p).toEqual({
			permissions: { dev: { network: { enabled: false } } },
		});
		expect(check(stringify(p), noDomains).findings).toEqual([]);
	});

	it("a proposal built from no-sandbox has no reject or narrow findings", () => {
		const p = proposal('sandbox_mode = "danger-full-access"\n');
		expect(
			check(stringify(p)).findings.filter((f) => f.verdict !== "keep"),
		).toEqual([]);
	});
});

describe("comparing network scope when both are set", () => {
	it("removes the profile when it allows network and is broader than the legacy setting without network", () => {
		const toml = [
			'sandbox_mode = "workspace-write"',
			'default_permissions = "a"',
			"[features]",
			"network_proxy = true",
			"[permissions.a]",
			'extends = ":workspace"',
			"[permissions.a.network]",
			"enabled = true",
			"[permissions.a.network.domains]",
			'"github.com" = "allow"',
			"",
		].join("\n");
		const p = proposal(toml) as Record<string, unknown>;
		expect(p.sandbox_mode).toBe("workspace-write");
		expect(p.default_permissions).toBeUndefined();
	});
});

describe("[features.network_proxy] as a table", () => {
	it("treats enabled = true in the table as the proxy being on", () => {
		const toml =
			'[features.network_proxy]\nenabled = true\n[permissions.dev.network]\nenabled = true\n[permissions.dev.network.domains]\n"api.openai.com" = "allow"\n';
		expect(check(toml).findings).toEqual([]);
	});

	it("treats a table without enabled = true as the proxy being off", () => {
		const toml =
			'[features.network_proxy]\nproxy_url = "http://127.0.0.1:3128"\n[permissions.dev.network]\nenabled = true\n[permissions.dev.network.domains]\n"api.openai.com" = "allow"\n';
		expect(check(toml).findings[0]?.ruleId).toBe("codex/network-all");
	});

	it("turns the proxy on inside the table instead of replacing the table", () => {
		const toml =
			'[features.network_proxy]\nproxy_url = "http://127.0.0.1:3128"\n[permissions.dev.network]\nenabled = true\n';
		expect(proposal(toml).features).toEqual({
			network_proxy: { proxy_url: "http://127.0.0.1:3128", enabled: true },
		});
	});
});

describe("write scope of a profile when compared with sandbox_mode", () => {
	it("treats a profile without extends as granting only what its filesystem table lists", () => {
		const toml = [
			'sandbox_mode = "read-only"',
			'default_permissions = "a"',
			"[permissions.a.filesystem]",
			'":minimal" = "read"',
			'[permissions.a.filesystem.":workspace_roots"]',
			'"." = "read"',
			"",
		].join("\n");
		const p = proposal(toml) as Record<string, unknown>;
		expect(p.sandbox_mode).toBeUndefined();
		expect(p.default_permissions).toBe("a");
	});

	it("counts write entries added on top of a read-only parent", () => {
		const toml = [
			'sandbox_mode = "read-only"',
			'default_permissions = "a"',
			"[permissions.a]",
			'extends = ":read-only"',
			'[permissions.a.filesystem.":workspace_roots"]',
			'"." = "write"',
			"",
		].join("\n");
		const p = proposal(toml) as Record<string, unknown>;
		expect(p.sandbox_mode).toBe("read-only");
		expect(p.default_permissions).toBeUndefined();
	});
});
