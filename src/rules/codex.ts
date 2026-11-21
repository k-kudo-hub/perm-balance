import { homedir } from "node:os";
import {
	homeWriteCandidates,
	networkDomains,
	SECRET_SCAN_DEPTH,
	secretDenyGlobs,
} from "../project.js";
import type { Patch, Recommendation, Suggestion } from "../types.js";
import {
	type Assessment,
	get,
	isObj,
	type RuleContext,
	type RuleResult,
	stringArray,
	toFinding,
} from "./common.js";

const BUILTIN_RANK: Record<string, number> = {
	":read-only": 0,
	":workspace": 1,
	":danger-full-access": 2,
};
const SANDBOX_MODE_RANK: Record<string, number> = {
	"read-only": 0,
	"workspace-write": 1,
	"danger-full-access": 2,
};

function isHomeOrRoot(path: string): boolean {
	const p = path.replace(/\/$/, "");
	return p === "~" || p === ":root" || p === homedir() || path === "/";
}

function customProfiles(config: unknown): Record<string, unknown> {
	const permissions = get(config, ["permissions"]);
	return isObj(permissions) ? permissions : {};
}

interface ProfileChain {
	/** Names of the profiles from the given one to its farthest parent */
	names: string[];
	/** Named profiles from the given one to its farthest parent */
	profiles: unknown[];
	/** The built-in profile the chain ends at, if any */
	builtin?: string;
}

/** Follows `extends` from a profile to a built-in profile or to a profile without `extends` */
function profileChain(config: unknown, name: string): ProfileChain {
	const names: string[] = [];
	const profiles: unknown[] = [];
	let current: unknown = name;
	for (let i = 0; i < 10 && typeof current === "string"; i++) {
		if (BUILTIN_RANK[current] !== undefined)
			return { names, profiles, builtin: current };
		const profile = customProfiles(config)[current];
		names.push(current);
		profiles.push(profile);
		current = get(profile, ["extends"]);
	}
	return { names, profiles };
}

/** Whether a filesystem table grants `write` anywhere, including nested subpaths */
function grantsWrite(filesystem: unknown): boolean {
	if (!isObj(filesystem)) return false;
	return Object.values(filesystem).some(
		(v) => v === "write" || (isObj(v) && Object.values(v).includes("write")),
	);
}

/**
 * How broad a profile is (0: read-only, 1: can write somewhere, 2: unrestricted).
 * A profile starts from its built-in parent, or from no access when it has no `extends`
 * ("Missing or empty filesystem tables keep filesystem access restricted"), and `write` entries add writes on top
 */
function profileRank(config: unknown, name: string): number {
	const chain = profileChain(config, name);
	const base = chain.builtin ? (BUILTIN_RANK[chain.builtin] ?? 0) : 0;
	const writes = chain.profiles.some((p) =>
		grantsWrite(get(p, ["filesystem"])),
	);
	return writes ? Math.max(base, 1) : base;
}

/** Domain rules in effect for a profile: the parents' rules, overridden by the child's */
function effectiveDomains(
	config: unknown,
	name: string,
): Record<string, unknown> {
	const chain = profileChain(config, name);
	const merged: Record<string, unknown> = {};
	for (const profile of [...chain.profiles].reverse()) {
		const domains = get(profile, ["network", "domains"]);
		if (isObj(domains)) Object.assign(merged, domains);
	}
	return merged;
}

/**
 * Whether a profile can write inside its workspace roots, decided by the nearest `:workspace_roots` rule for "."
 * in the chain, or by the built-in parent (:workspace writes there) when none sets it
 */
function workspaceRootsWritable(config: unknown, name: string): boolean {
	const chain = profileChain(config, name);
	for (const profile of chain.profiles) {
		const rule = get(profile, ["filesystem", ":workspace_roots"]);
		if (typeof rule === "string") return rule === "write";
		if (isObj(rule) && typeof rule["."] === "string")
			return rule["."] === "write";
	}
	return chain.builtin === ":workspace";
}

/** Whether a profile allows network access, resolved by following `extends` to the first profile that sets network.enabled, or to a built-in profile */
function profileNetwork(config: unknown, name: string): boolean {
	let current: unknown = name;
	for (let i = 0; i < 10 && typeof current === "string"; i++) {
		if (current === ":danger-full-access") return true;
		if (BUILTIN_RANK[current] !== undefined) return false;
		const profile = customProfiles(config)[current];
		const enabled = get(profile, ["network", "enabled"]);
		if (typeof enabled === "boolean") return enabled;
		current = get(profile, ["extends"]);
	}
	return false;
}

/** Whether the legacy settings allow network access */
function legacyNetwork(config: unknown, sandboxMode: string): boolean {
	if (sandboxMode === "danger-full-access") return true;
	return (
		sandboxMode === "workspace-write" &&
		get(config, ["sandbox_workspace_write", "network_access"]) === true
	);
}

/** Whether the network proxy is started: `[features] network_proxy = true`, or `enabled = true` in the `[features.network_proxy]` table */
function proxyOn(config: unknown): boolean {
	const proxy = get(config, ["features", "network_proxy"]);
	return proxy === true || (isObj(proxy) && proxy.enabled === true);
}

/** Patch that starts the proxy, keeping the other settings when `[features.network_proxy]` is a table */
function enableProxy(config: unknown): Patch {
	return isObj(get(config, ["features", "network_proxy"]))
		? { op: "set", path: ["features", "network_proxy", "enabled"], value: true }
		: { op: "set", path: ["features", "network_proxy"], value: true };
}

/** Name for a new profile that does not collide with an existing one */
function newProfileName(config: unknown): string {
	return "project" in customProfiles(config) ? "project-narrow" : "project";
}

/**
 * Patches that restrict destinations to this project's and enforce them with the proxy.
 * The proxy blocks external traffic when nothing is allowed, so with no candidate domains, turn the network off
 */
function narrowNetwork(
	config: unknown,
	profile: string,
	ctx: RuleContext,
	keepDomains: boolean,
): Patch[] {
	const base = ["permissions", profile, "network"];
	if (keepDomains) return [enableProxy(config)];
	const domains = networkDomains(ctx.facts);
	if (domains.length === 0) {
		return [
			{ op: "set", path: [...base, "enabled"], value: false },
			{ op: "delete", path: [...base, "domains", "*"] },
		];
	}
	return [
		{ op: "set", path: [...base, "enabled"], value: true },
		enableProxy(config),
		{ op: "delete", path: [...base, "domains", "*"] },
		...domains.map(
			(d): Patch => ({
				op: "set",
				path: [...base, "domains", d],
				value: "allow",
			}),
		),
	];
}

/** Patches that move from no sandbox or legacy settings to a profile that can write only the workspace and reach only allowed domains */
function migrateToProfile(config: unknown, ctx: RuleContext): Patch[] {
	const name = newProfileName(config);
	const roots = stringArray(
		get(config, ["sandbox_workspace_write", "writable_roots"]),
	).filter((p) => !isHomeOrRoot(p));
	return [
		{ op: "delete", path: ["sandbox_mode"] },
		{ op: "delete", path: ["sandbox_workspace_write"] },
		{ op: "set", path: ["default_permissions"], value: name },
		{ op: "set", path: ["permissions", name, "extends"], value: ":workspace" },
		...roots.map(
			(p): Patch => ({
				op: "set",
				path: ["permissions", name, "filesystem", p],
				value: "write",
			}),
		),
		...narrowNetwork(config, name, ctx, false),
	];
}

const NETWORK_RISK =
	"Commands can reach any host, and may send secrets out by following instructions they read";

/**
 * The dangerously_* network keys, which the docs call escape hatches for specialized environments
 * that "should not be used for ordinary local development". They can be set in a profile's network table
 * or in the [features.network_proxy] table
 */
function checkDangerousNetworkKeys(
	table: Record<string, unknown>,
	path: string[],
	label: string,
): Assessment[] {
	const out: Assessment[] = [];
	const remove = (key: string): Suggestion["patches"] => [
		{ op: "delete", path: [...path, key] },
	];
	if (table.dangerously_allow_all_unix_sockets === true) {
		out.push({
			ruleId: "codex/all-unix-sockets",
			setting: `${label} dangerously_allow_all_unix_sockets = true`,
			risk: "high",
			riskReason:
				"Reaches sockets such as Docker's, which control things outside the sandbox just by connecting",
			convenience: "low",
			convenienceReason:
				"Only a few sockets are needed, and [permissions.<name>.network.unix_sockets] can allow them one by one",
			suggestion: {
				summary:
					"Remove it and allow only the sockets you use with unix_sockets",
				patches: remove("dangerously_allow_all_unix_sockets"),
			},
		});
	}
	if (table.dangerously_allow_non_loopback_proxy === true) {
		out.push({
			ruleId: "codex/non-loopback-proxy",
			setting: `${label} dangerously_allow_non_loopback_proxy = true`,
			risk: "medium",
			riskReason:
				"Lets the proxy listen beyond localhost, so other machines on the network can reach it and send traffic through your allowed destinations",
			convenience: "low",
			convenienceReason:
				"Commands in the sandbox reach the proxy on localhost, so ordinary local development does not need it",
			suggestion: {
				summary: "Remove it so the proxy listens only on localhost",
				patches: remove("dangerously_allow_non_loopback_proxy"),
			},
		});
	}
	return out;
}

function checkProfile(
	name: string,
	profile: unknown,
	config: unknown,
	ctx: RuleContext,
): Assessment[] {
	const out: Assessment[] = [];
	const fsPath = ["permissions", name, "filesystem"];
	const fs = get(profile, ["filesystem"]);
	if (isObj(fs)) {
		for (const [path, value] of Object.entries(fs)) {
			const writes =
				value === "write" || (isObj(value) && value["."] === "write");
			if (!writes || !isHomeOrRoot(path)) continue;
			out.push({
				ruleId: "codex/write-home",
				setting: `[permissions.${name}.filesystem] "${path}" = "write"`,
				risk: "high",
				riskReason:
					"Can write anywhere under your home or the root, so it can rewrite shell configs or SSH keys and run code on the next launch",
				convenience: "medium",
				convenienceReason: "Tools never stop on writes to caches or config",
				suggestion: {
					summary:
						"Allow writes only to the cache directories this project's tools use",
					patches: [
						{ op: "delete", path: [...fsPath, path] },
						...homeWriteCandidates(ctx.facts).map(
							(dir): Patch => ({
								op: "set",
								path: [...fsPath, dir],
								value: "write",
							}),
						),
					],
				},
			});
		}
	}

	const roots = get(profile, ["workspace_roots"]);
	if (isObj(roots) && workspaceRootsWritable(config, name)) {
		for (const [path, enabled] of Object.entries(roots)) {
			if (enabled !== true || !isHomeOrRoot(path)) continue;
			out.push({
				ruleId: "codex/write-home",
				setting: `[permissions.${name}.workspace_roots] "${path}" = true`,
				risk: "high",
				riskReason:
					"Makes your home or the root a workspace root, which this profile can write, so it can rewrite shell configs or SSH keys and run code on the next launch",
				convenience: "medium",
				convenienceReason: "Tools never stop on writes to caches or config",
				suggestion: {
					summary:
						"Remove it and allow writes only to the cache directories this project's tools use",
					patches: [
						{
							op: "delete",
							path: ["permissions", name, "workspace_roots", path],
						},
						...homeWriteCandidates(ctx.facts).map(
							(dir): Patch => ({
								op: "set",
								path: [...fsPath, dir],
								value: "write",
							}),
						),
					],
				},
			});
		}
	}

	const network = get(profile, ["network"]);
	if (!isObj(network)) return out;
	if (network.enabled === true) {
		// Domain rules are inherited through extends
		const domains = effectiveDomains(config, name);
		const allowAll = domains["*"] === "allow";
		const hasAllow = Object.values(domains).includes("allow");
		const proxy = proxyOn(config);
		// With the proxy on and no "*" allowed, only allowed domains are reachable (none at all if nothing is allowed)
		if (allowAll || !proxy) {
			const why = allowAll
				? '"*" = "allow" allows every destination'
				: hasAllow
					? "Domains are listed, but [features] network_proxy is off, so the list is not enforced and every destination is reachable"
					: "The network is on with no domain list and [features] network_proxy is off, so every destination is reachable";
			const keepDomains = hasAllow && !allowAll;
			out.push({
				ruleId: "codex/network-all",
				setting: `[permissions.${name}.network] enabled = true`,
				risk: "high",
				riskReason: `${why}. ${NETWORK_RISK}`,
				convenience: "high",
				convenienceReason: "Never stops on package downloads or API calls",
				suggestion: {
					summary: keepDomains
						? "Turn on [features] network_proxy so the domain list is enforced"
						: "Allow only the package registries and Git hosts this project uses, enforced by the proxy (turn the network off if there are none)",
					patches: [
						...narrowNetwork(config, name, ctx, keepDomains),
						// A "*" inherited from a parent cannot be overridden ("*" is allow-only), so remove it from the parent
						...profileChain(config, name)
							.names.slice(1)
							.filter(
								(parent) =>
									get(customProfiles(config)[parent], [
										"network",
										"domains",
										"*",
									]) === "allow",
							)
							.map(
								(parent): Patch => ({
									op: "delete",
									path: ["permissions", parent, "network", "domains", "*"],
								}),
							),
					],
				},
			});
		}
	}
	out.push(
		...checkDangerousNetworkKeys(
			network,
			["permissions", name, "network"],
			`[permissions.${name}.network]`,
		),
	);
	return out;
}

/** Checks for when the legacy sandbox_mode is in effect */
function checkLegacy(
	config: unknown,
	ctx: RuleContext,
	sandboxMode: unknown,
): Assessment[] {
	const out: Assessment[] = [];
	const approval = get(config, ["approval_policy"]);
	if (sandboxMode === "danger-full-access") {
		out.push(
			fullAccess(
				'sandbox_mode = "danger-full-access"',
				approval,
				migrateToProfile(config, ctx),
			),
		);
		return out;
	}
	const legacy = get(config, ["sandbox_workspace_write"]);
	if (sandboxMode !== "workspace-write" || !isObj(legacy)) return out;
	if (legacy.network_access === true) {
		out.push({
			ruleId: "codex/legacy-network-all",
			setting: "[sandbox_workspace_write] network_access = true",
			risk: "high",
			riskReason: `The legacy settings cannot restrict destinations. ${NETWORK_RISK}`,
			convenience: "high",
			convenienceReason: "Never stops on package downloads or API calls",
			suggestion: {
				summary:
					"Move to a permission profile and allow only the destinations this project uses",
				patches: migrateToProfile(config, ctx),
			},
		});
	}
	for (const root of stringArray(legacy.writable_roots)) {
		if (!isHomeOrRoot(root)) continue;
		const rootsPath = ["sandbox_workspace_write", "writable_roots"];
		out.push({
			ruleId: "codex/legacy-write-home",
			setting: `[sandbox_workspace_write] writable_roots = ["${root}"]`,
			risk: "high",
			riskReason:
				"Can write anywhere under your home or the root, so it can rewrite shell configs or SSH keys",
			convenience: "medium",
			convenienceReason: "Tools never stop on writes to caches or config",
			suggestion: {
				summary:
					"Remove it and add only the cache directories this project's tools use",
				patches: [
					{ op: "remove-from-array", path: rootsPath, values: [root] },
					{
						op: "add-to-array",
						path: rootsPath,
						values: homeWriteCandidates(ctx.facts),
					},
				],
			},
		});
	}
	return out;
}

function fullAccess(
	setting: string,
	approval: unknown,
	patches: Patch[],
): Assessment {
	const noApproval =
		approval === "never"
			? '. Combined with approval_policy = "never", nothing is confirmed before it runs'
			: "";
	return {
		ruleId: "codex/danger-full-access",
		setting,
		risk: "high",
		riskReason: `Runs without a sandbox, allowing writes to the whole filesystem and traffic to every destination${noApproval}`,
		convenience: "high",
		convenienceReason: "Work never stops on writes or network access",
		suggestion: {
			summary:
				"Use a profile built on :workspace (writes only to the workspace) that reaches only the destinations this project uses",
			patches,
		},
	};
}

export function checkCodexConfig(
	config: unknown,
	ctx: RuleContext,
): RuleResult {
	const assessments: Assessment[] = [];
	const sandboxMode = get(config, ["sandbox_mode"]);
	const defaultPermissions = get(config, ["default_permissions"]);
	const dp =
		typeof defaultPermissions === "string" ? defaultPermissions : undefined;

	// default_permissions is ignored while sandbox_mode is set. When both exist, remove the broader one so the narrower one applies
	let legacyEffective = sandboxMode !== undefined;
	if (dp !== undefined && typeof sandboxMode === "string") {
		// If the profile is broader in either writes or network access, remove the profile
		const profileWider =
			profileRank(config, dp) > (SANDBOX_MODE_RANK[sandboxMode] ?? 1) ||
			(profileNetwork(config, dp) && !legacyNetwork(config, sandboxMode));
		legacyEffective = profileWider;
		const setting = `default_permissions = "${dp}" and sandbox_mode = "${sandboxMode}"`;
		assessments.push(
			profileWider
				? {
						ruleId: "codex/profile-ignored",
						setting,
						risk: "medium",
						riskReason:
							"sandbox_mode is what applies, and the unused default_permissions is broader. Removing sandbox_mode would widen permissions",
						convenience: "low",
						convenienceReason: "Keeping an unused setting gains nothing",
						suggestion: {
							summary: "Remove the unused default_permissions",
							patches: [{ op: "delete", path: ["default_permissions"] }],
						},
					}
				: {
						ruleId: "codex/profile-ignored",
						setting,
						risk: "medium",
						riskReason:
							"The default_permissions profile is ignored while sandbox_mode is set, so the restrictions you wrote are not in effect",
						convenience: "low",
						convenienceReason: "Writing both gains nothing",
						suggestion: {
							summary:
								"Remove the legacy sandbox_mode and [sandbox_workspace_write] so the profile applies",
							patches: [
								{ op: "delete", path: ["sandbox_mode"] },
								{ op: "delete", path: ["sandbox_workspace_write"] },
							],
						},
					},
		);
	}

	if (legacyEffective) {
		assessments.push(...checkLegacy(config, ctx, sandboxMode));
	} else if (dp === ":danger-full-access") {
		assessments.push(
			fullAccess(
				'default_permissions = ":danger-full-access"',
				get(config, ["approval_policy"]),
				migrateToProfile(config, ctx),
			),
		);
	}

	const proxyTable = get(config, ["features", "network_proxy"]);
	if (isObj(proxyTable)) {
		assessments.push(
			...checkDangerousNetworkKeys(
				proxyTable,
				["features", "network_proxy"],
				"[features.network_proxy]",
			),
		);
	}

	for (const [name, profile] of Object.entries(customProfiles(config))) {
		assessments.push(...checkProfile(name, profile, config, ctx));
	}

	const recommendations: Recommendation[] = [];
	const globs = secretDenyGlobs(ctx.facts);
	if (
		ctx.scope === "project" &&
		!legacyEffective &&
		dp !== ":danger-full-access" &&
		globs.length > 0
	) {
		const useActive = dp !== undefined && BUILTIN_RANK[dp] === undefined;
		const name = useActive ? dp : newProfileName(config);
		const rootsPath = ["permissions", name, "filesystem", ":workspace_roots"];
		const existing = useActive ? get(config, rootsPath) : undefined;
		const missing = globs.filter(
			(g) => !(isObj(existing) && existing[g] === "deny"),
		);
		if (missing.length > 0) {
			const create: Patch[] = useActive
				? []
				: [
						{ op: "set", path: ["default_permissions"], value: name },
						{
							op: "set",
							path: ["permissions", name, "extends"],
							value: dp === ":read-only" ? ":read-only" : ":workspace",
						},
					];
			// On Linux, WSL and native Windows, an unbounded ** deny pattern needs bounded pre-expansion.
			// Use the depth perm-balance scans for secret files, and keep a value the user already set
			const depthPath = [
				"permissions",
				name,
				"filesystem",
				"glob_scan_max_depth",
			];
			const depth: Patch[] =
				useActive && get(config, depthPath) !== undefined
					? []
					: [{ op: "set", path: depthPath, value: SECRET_SCAN_DEPTH }];
			recommendations.push({
				ruleId: "codex/deny-secrets",
				agent: "codex",
				file: ctx.file,
				summary: `Deny reads of secret files (${ctx.facts.secretFiles.join(", ")})`,
				reason:
					"Work rarely needs to read secrets, so denying them costs almost nothing",
				patches: [
					...create,
					...depth,
					...missing.map(
						(g): Patch => ({
							op: "set",
							path: [...rootsPath, g],
							value: "deny",
						}),
					),
				],
			});
		}
	}

	return {
		findings: assessments.map((a) => toFinding("codex", ctx, a)),
		recommendations,
	};
}
