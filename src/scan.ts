import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { parse, stringify } from "smol-toml";
import { applyPatches } from "./patch.js";
import { readProjectFacts } from "./project.js";
import { checkClaudeSettings } from "./rules/claude.js";
import { checkCodexConfig } from "./rules/codex.js";
import type { RuleResult } from "./rules/common.js";
import type { Agent, FileReport, Scope } from "./types.js";

export interface ScanOptions {
	/** 点検するプロジェクトのディレクトリ */
	root: string;
	/** ユーザーのホームディレクトリ */
	home: string;
	/** ユーザー全体の設定（~/.claude/settings.json・~/.codex/config.toml）も点検する */
	includeUser: boolean;
	/** 追加で点検するファイル */
	files: string[];
}

interface Target {
	path: string;
	agent: Agent;
	scope: Scope;
}

function scopeOf(path: string, home: string): Scope {
	const userDirs = [join(home, ".claude"), join(home, ".codex")];
	return userDirs.some((dir) => !relative(dir, path).startsWith(".."))
		? "user"
		: "project";
}

function discover(opts: ScanOptions): Target[] {
	const candidates: Target[] = [
		{
			path: join(opts.root, ".claude/settings.json"),
			agent: "claude-code",
			scope: "project",
		},
		{
			path: join(opts.root, ".claude/settings.local.json"),
			agent: "claude-code",
			scope: "project",
		},
		{
			path: join(opts.root, ".codex/config.toml"),
			agent: "codex",
			scope: "project",
		},
	];
	if (opts.includeUser) {
		candidates.push(
			{
				path: join(opts.home, ".claude/settings.json"),
				agent: "claude-code",
				scope: "user",
			},
			{
				path: join(opts.home, ".codex/config.toml"),
				agent: "codex",
				scope: "user",
			},
		);
	}
	const targets = candidates.filter((t) => existsSync(t.path));
	for (const file of opts.files) {
		const path = resolve(file);
		if (targets.some((t) => t.path === path)) continue;
		targets.push({
			path,
			agent: path.endsWith(".toml") ? "codex" : "claude-code",
			scope: scopeOf(path, opts.home),
		});
	}
	return targets;
}

function displayPath(path: string, opts: ScanOptions): string {
	const fromRoot = relative(opts.root, path);
	if (!fromRoot.startsWith("..") && !isAbsolute(fromRoot)) return fromRoot;
	const fromHome = relative(opts.home, path);
	if (!fromHome.startsWith("..") && !isAbsolute(fromHome))
		return `~/${fromHome}`;
	return path;
}

export function scan(opts: ScanOptions): FileReport[] {
	const facts = readProjectFacts(opts.root);
	return discover(opts).map((target) => {
		const file = displayPath(target.path, opts);
		const base = {
			file,
			agent: target.agent,
			scope: target.scope,
			findings: [],
			recommendations: [],
		};
		let config: unknown;
		try {
			const text = readFileSync(target.path, "utf8");
			config = target.agent === "codex" ? parse(text) : JSON.parse(text);
		} catch (e) {
			return { ...base, error: e instanceof Error ? e.message : String(e) };
		}
		const ctx = { file, scope: target.scope, facts };
		const result: RuleResult =
			target.agent === "codex"
				? checkCodexConfig(config, ctx)
				: checkClaudeSettings(config, ctx);
		const patches = [
			...result.findings
				.filter((f) => f.verdict !== "keep")
				.flatMap((f) => f.suggestion?.patches ?? []),
			...result.recommendations.flatMap((r) => r.patches),
		];
		let proposal: string | undefined;
		if (patches.length > 0) {
			const proposed = applyPatches(config, patches) as Record<string, unknown>;
			proposal =
				target.agent === "codex"
					? stringify(proposed)
					: `${JSON.stringify(proposed, null, 2)}\n`;
		}
		return { ...base, ...result, proposal };
	});
}
