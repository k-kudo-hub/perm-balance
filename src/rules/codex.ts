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

const BUILTIN_PROFILES = new Set([
	":read-only",
	":workspace",
	":danger-full-access",
]);

function isHomeOrRoot(path: string): boolean {
	const home = homedir();
	const p = path.replace(/\/$/, "");
	return p === "~" || p === ":root" || p === home || path === "/";
}

function customProfiles(config: unknown): Record<string, unknown> {
	const permissions = get(config, ["permissions"]);
	return isObj(permissions) ? permissions : {};
}

/** 新しく作るプロファイルの名前。既存のものと重ならないようにする */
function newProfileName(config: unknown): string {
	const existing = customProfiles(config);
	return "project" in existing ? "project-narrow" : "project";
}

/** 宛先をこのプロジェクトのものに絞り、プロキシで強制するための変更 */
function narrowNetwork(
	profile: string,
	ctx: RuleContext,
	keepDomains: boolean,
): Patch[] {
	const base = ["permissions", profile, "network"];
	const patches: Patch[] = [
		{ op: "set", path: [...base, "enabled"], value: true },
		{ op: "set", path: ["features", "network_proxy"], value: true },
	];
	if (!keepDomains) {
		patches.push({ op: "delete", path: [...base, "domains", "*"] });
		for (const d of networkDomains(ctx.facts)) {
			patches.push({
				op: "set",
				path: [...base, "domains", d],
				value: "allow",
			});
		}
	}
	return patches;
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

function checkProfile(
	name: string,
	profile: unknown,
	config: unknown,
	ctx: RuleContext,
): Assessment[] {
	const out: Assessment[] = [];
	const fs = get(profile, ["filesystem"]);
	if (isObj(fs)) {
		for (const [path, value] of Object.entries(fs)) {
			const writes =
				value === "write" || (isObj(value) && value["."] === "write");
			if (!writes || !isHomeOrRoot(path)) continue;
			const fsPath = ["permissions", name, "filesystem"];
			out.push({
				ruleId: "codex/write-home",
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
	if (isObj(network)) {
		if (network.enabled === true) {
			const domains = get(network, ["domains"]);
			const allowAll = isObj(domains) && domains["*"] === "allow";
			const hasAllow =
				isObj(domains) && Object.values(domains).includes("allow");
			const proxy = get(config, ["features", "network_proxy"]) === true;
			if (allowAll || !hasAllow || !proxy) {
				const why = allowAll
					? '"*" = "allow" ですべての宛先を許可している'
					: !hasAllow
						? "宛先を決めずにネットワークを有効にしている"
						: "宛先を絞っているが、[features] network_proxy を有効にしていないため、宛先の指定が効かない";
				out.push({
					ruleId: "codex/network-all",
					setting: `[permissions.${name}.network] enabled = true`,
					risk: "high",
					riskReason: `${why}。コマンドがどこへでも通信でき、読み込んだ指示に従って秘密情報を送るおそれがある`,
					convenience: "high",
					convenienceReason: "パッケージの取得や API の呼び出しで止まらない",
					suggestion: {
						summary:
							hasAllow && !allowAll
								? "[features] network_proxy を有効にして、宛先の指定を効かせる"
								: "このプロジェクトが使うパッケージレジストリと Git のホストだけを許可し、プロキシで強制する",
						patches: narrowNetwork(name, ctx, hasAllow && !allowAll),
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
	}
	return out;
}

export function checkCodexConfig(
	config: unknown,
	ctx: RuleContext,
): RuleResult {
	const assessments: Assessment[] = [];
	const sandboxMode = get(config, ["sandbox_mode"]);
	const defaultPermissions = get(config, ["default_permissions"]);
	const approval = get(config, ["approval_policy"]);

	const fullAccess =
		sandboxMode === "danger-full-access"
			? 'sandbox_mode = "danger-full-access"'
			: defaultPermissions === ":danger-full-access" &&
					sandboxMode === undefined
				? 'default_permissions = ":danger-full-access"'
				: undefined;
	if (fullAccess) {
		const noApproval =
			approval === "never"
				? '。approval_policy = "never" と組み合わさり、実行前の確認もない'
				: "";
		assessments.push({
			ruleId: "codex/danger-full-access",
			setting: fullAccess,
			risk: "high",
			riskReason: `サンドボックスを使わず、ファイルシステム全体への書き込みとすべての宛先への通信を許す${noApproval}`,
			convenience: "high",
			convenienceReason: "書き込み先や通信で止まらずに作業できる",
			suggestion: {
				summary:
					"ワークスペースだけを書き込み可にする :workspace を土台に、このプロジェクトが使う宛先だけ通信を許すプロファイルにする",
				patches: migrateToProfile(config, ctx),
			},
		});
	}

	const legacy = get(config, ["sandbox_workspace_write"]);
	if (!fullAccess && sandboxMode === "workspace-write" && isObj(legacy)) {
		if (legacy.network_access === true) {
			assessments.push({
				ruleId: "codex/legacy-network-all",
				setting: "[sandbox_workspace_write] network_access = true",
				risk: "high",
				riskReason: "宛先を問わず通信できる。旧来の設定では宛先を絞れない",
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
			assessments.push({
				ruleId: "codex/legacy-write-home",
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
						{
							op: "remove-from-array",
							path: ["sandbox_workspace_write", "writable_roots"],
							values: [root],
						},
						{
							op: "add-to-array",
							path: ["sandbox_workspace_write", "writable_roots"],
							values: homeWriteCandidates(ctx.facts),
						},
					],
				},
			});
		}
	}

	if (
		defaultPermissions !== undefined &&
		sandboxMode !== undefined &&
		!fullAccess
	) {
		assessments.push({
			ruleId: "codex/profile-ignored",
			setting: `default_permissions = "${String(defaultPermissions)}" と sandbox_mode = "${String(sandboxMode)}"`,
			risk: "medium",
			riskReason:
				"sandbox_mode があると default_permissions のプロファイルは使われないため、書いた制限が効いていない",
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
		});
	}

	for (const [name, profile] of Object.entries(customProfiles(config))) {
		assessments.push(...checkProfile(name, profile, config, ctx));
	}

	const recommendations: Recommendation[] = [];
	const globs = secretDenyGlobs(ctx.facts);
	if (
		ctx.scope === "project" &&
		sandboxMode === undefined &&
		globs.length > 0
	) {
		const active =
			typeof defaultPermissions === "string" ? defaultPermissions : undefined;
		const useActive = active !== undefined && !BUILTIN_PROFILES.has(active);
		const name = useActive ? active : newProfileName(config);
		const rootsPath = ["permissions", name, "filesystem", ":workspace_roots"];
		const existing = useActive ? get(config, rootsPath) : undefined;
		const missing = globs.filter(
			(g) => !(isObj(existing) && existing[g] === "deny"),
		);
		if (missing.length > 0) {
			const parent = active === ":read-only" ? ":read-only" : ":workspace";
			recommendations.push({
				ruleId: "codex/deny-secrets",
				agent: "codex",
				file: ctx.file,
				summary: `秘密情報のファイル（${ctx.facts.secretFiles.join("、")}）を読ませない`,
				reason:
					"作業で秘密情報を読む必要はほとんどなく、拒否しても利便性はほとんど落ちない",
				patches: [
					...(useActive
						? []
						: [
								{
									op: "set",
									path: ["default_permissions"],
									value: name,
								} as Patch,
								{
									op: "set",
									path: ["permissions", name, "extends"],
									value: parent,
								} as Patch,
							]),
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
		findings: assessments.map((a) => toFinding("codex", ctx.file, a)),
		recommendations,
	};
}
