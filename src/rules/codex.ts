import { homedir } from "node:os";
import {
	homeWriteCandidates,
	networkDomains,
	secretDenyGlobs,
} from "../project.js";
import type { Patch, Recommendation } from "../types.js";
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

/** プロファイルの広さ（0: 読むだけ・1: ワークスペースに書ける・2: 制限なし）。extends をたどって標準のプロファイルで決める */
function profileRank(config: unknown, name: string): number {
	let current: unknown = name;
	for (let i = 0; i < 10 && typeof current === "string"; i++) {
		const builtin = BUILTIN_RANK[current];
		if (builtin !== undefined) return builtin;
		current = get(customProfiles(config)[current], ["extends"]);
	}
	// extends がないプロファイルの土台は文書で決まっていないため、標準の :workspace と同じとみなす
	return 1;
}

/** プロファイルで通信できるか。extends をたどり、最初に network.enabled を書いたものか標準のプロファイルで決める */
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

/** 旧来の設定で通信できるか */
function legacyNetwork(config: unknown, sandboxMode: string): boolean {
	if (sandboxMode === "danger-full-access") return true;
	return (
		sandboxMode === "workspace-write" &&
		get(config, ["sandbox_workspace_write", "network_access"]) === true
	);
}

/** 新しく作るプロファイルの名前。既存のものと重ならないようにする */
function newProfileName(config: unknown): string {
	return "project" in customProfiles(config) ? "project-narrow" : "project";
}

/**
 * 宛先をこのプロジェクトのものに絞り、プロキシで強制するための変更。
 * プロキシは許可した宛先がなければ外への通信を止めるため、宛先の候補がなければネットワークを切る
 */
function narrowNetwork(
	profile: string,
	ctx: RuleContext,
	keepDomains: boolean,
): Patch[] {
	const base = ["permissions", profile, "network"];
	if (keepDomains)
		return [{ op: "set", path: ["features", "network_proxy"], value: true }];
	const domains = networkDomains(ctx.facts);
	if (domains.length === 0) {
		return [
			{ op: "set", path: [...base, "enabled"], value: false },
			{ op: "delete", path: [...base, "domains", "*"] },
		];
	}
	return [
		{ op: "set", path: [...base, "enabled"], value: true },
		{ op: "set", path: ["features", "network_proxy"], value: true },
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

/** サンドボックスなし・旧来の設定から、ワークスペースだけ書けて宛先を絞ったプロファイルに移す変更 */
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
		...narrowNetwork(name, ctx, false),
	];
}

const NETWORK_RISK =
	"コマンドがどこへでも通信でき、読み込んだ指示に従って秘密情報を送るおそれがある";

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
				usesFacts: true,
				setting: `[permissions.${name}.filesystem] "${path}" = "write"`,
				risk: "high",
				riskReason:
					"ホームかルートの下のどこにでも書き込めるため、シェルの設定や SSH の鍵を書き換えて、次の起動時にコードを動かせる",
				convenience: "medium",
				convenienceReason: "ツールのキャッシュや設定の書き込みで止まらない",
				suggestion: {
					summary:
						"このプロジェクトのツールが使うキャッシュの場所だけを書き込み可にする",
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

	const network = get(profile, ["network"]);
	if (!isObj(network)) return out;
	if (network.enabled === true) {
		const domains = get(network, ["domains"]);
		const allowAll = isObj(domains) && domains["*"] === "allow";
		const hasAllow = isObj(domains) && Object.values(domains).includes("allow");
		const proxy = get(config, ["features", "network_proxy"]) === true;
		// プロキシが有効で "*" を許可していなければ、通信できるのは許可した宛先だけ（許可がなければ外へは通信できない）
		if (allowAll || !proxy) {
			const why = allowAll
				? '"*" = "allow" ですべての宛先を許可している'
				: hasAllow
					? "宛先を絞っているが、[features] network_proxy を有効にしていないため、宛先の指定が効かずすべての宛先に通信できる"
					: "宛先を決めずにネットワークを有効にしており、[features] network_proxy も無効なため、すべての宛先に通信できる";
			const keepDomains = hasAllow && !allowAll;
			out.push({
				ruleId: "codex/network-all",
				usesFacts: !keepDomains,
				setting: `[permissions.${name}.network] enabled = true`,
				risk: "high",
				riskReason: `${why}。${NETWORK_RISK}`,
				convenience: "high",
				convenienceReason: "パッケージの取得や API の呼び出しで止まらない",
				suggestion: {
					summary: keepDomains
						? "[features] network_proxy を有効にして、宛先の指定を効かせる"
						: "このプロジェクトが使うパッケージレジストリと Git のホストだけを許可し、プロキシで強制する（宛先の候補がなければネットワークを切る）",
					patches: narrowNetwork(name, ctx, keepDomains),
				},
			});
		}
	}
	if (network.dangerously_allow_all_unix_sockets === true) {
		out.push({
			ruleId: "codex/all-unix-sockets",
			setting: `[permissions.${name}.network] dangerously_allow_all_unix_sockets = true`,
			risk: "high",
			riskReason:
				"Docker のソケットのような、つなぐだけでサンドボックスの外を操作できるソケットにも届く",
			convenience: "low",
			convenienceReason:
				"使うソケットは限られ、[permissions.<名前>.network.unix_sockets] で個別に許可すれば足りる",
			suggestion: {
				summary: "外して、使うソケットだけを unix_sockets で許可する",
				patches: [
					{
						op: "delete",
						path: [
							"permissions",
							name,
							"network",
							"dangerously_allow_all_unix_sockets",
						],
					},
				],
			},
		});
	}
	return out;
}

/** 旧来の sandbox_mode が効いているときの点検 */
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
			usesFacts: true,
			setting: "[sandbox_workspace_write] network_access = true",
			risk: "high",
			riskReason: `旧来の設定では宛先を絞れない。${NETWORK_RISK}`,
			convenience: "high",
			convenienceReason: "パッケージの取得や API の呼び出しで止まらない",
			suggestion: {
				summary:
					"権限プロファイルに移し、このプロジェクトが使う宛先だけを許可する",
				patches: migrateToProfile(config, ctx),
			},
		});
	}
	for (const root of stringArray(legacy.writable_roots)) {
		if (!isHomeOrRoot(root)) continue;
		const rootsPath = ["sandbox_workspace_write", "writable_roots"];
		out.push({
			ruleId: "codex/legacy-write-home",
			usesFacts: true,
			setting: `[sandbox_workspace_write] writable_roots = ["${root}"]`,
			risk: "high",
			riskReason:
				"ホームかルートの下のどこにでも書き込めるため、シェルの設定や SSH の鍵を書き換えられる",
			convenience: "medium",
			convenienceReason: "ツールのキャッシュや設定の書き込みで止まらない",
			suggestion: {
				summary:
					"外して、このプロジェクトのツールが使うキャッシュの場所だけを加える",
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
			? '。approval_policy = "never" と組み合わさり、実行前の確認もない'
			: "";
	return {
		ruleId: "codex/danger-full-access",
		usesFacts: true,
		setting,
		risk: "high",
		riskReason: `サンドボックスを使わず、ファイルシステム全体への書き込みとすべての宛先への通信を許す${noApproval}`,
		convenience: "high",
		convenienceReason: "書き込み先や通信で止まらずに作業できる",
		suggestion: {
			summary:
				"ワークスペースだけを書き込み可にする :workspace を土台に、このプロジェクトが使う宛先だけ通信を許すプロファイルにする",
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

	// sandbox_mode があると default_permissions は使われない。両方あるときは、広いほうを消して狭いほうを効かせる
	let legacyEffective = sandboxMode !== undefined;
	if (dp !== undefined && typeof sandboxMode === "string") {
		// 書き込みの範囲か通信のどちらかでプロファイルのほうが広ければ、プロファイルを消す
		const profileWider =
			profileRank(config, dp) > (SANDBOX_MODE_RANK[sandboxMode] ?? 1) ||
			(profileNetwork(config, dp) && !legacyNetwork(config, sandboxMode));
		legacyEffective = profileWider;
		const setting = `default_permissions = "${dp}" と sandbox_mode = "${sandboxMode}"`;
		assessments.push(
			profileWider
				? {
						ruleId: "codex/profile-ignored",
						setting,
						risk: "medium",
						riskReason:
							"効いているのは sandbox_mode で、使われていない default_permissions のほうが広い。sandbox_mode を消すと権限が広がる",
						convenience: "low",
						convenienceReason: "使われていない設定を残しても得られるものはない",
						suggestion: {
							summary: "使われていない default_permissions を消す",
							patches: [{ op: "delete", path: ["default_permissions"] }],
						},
					}
				: {
						ruleId: "codex/profile-ignored",
						setting,
						risk: "medium",
						riskReason:
							"sandbox_mode があると default_permissions のプロファイルは使われないため、書いたプロファイルの制限が効いていない",
						convenience: "low",
						convenienceReason: "両方を書いても得られるものはない",
						suggestion: {
							summary:
								"旧来の sandbox_mode と [sandbox_workspace_write] を消し、プロファイルを効かせる",
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
			recommendations.push({
				ruleId: "codex/deny-secrets",
				agent: "codex",
				file: ctx.file,
				summary: `秘密情報のファイル（${ctx.facts.secretFiles.join("、")}）を読ませない`,
				reason:
					"作業で秘密情報を読む必要はほとんどなく、拒否しても利便性はほとんど落ちない",
				patches: [
					...create,
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
