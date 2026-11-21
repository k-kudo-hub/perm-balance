import type { ProjectFacts } from "../project.js";
import type {
	Agent,
	Finding,
	Level,
	Recommendation,
	Scope,
	Suggestion,
} from "../types.js";
import { decideVerdict } from "../verdict.js";

export interface RuleContext {
	/** 表示用のファイルのパス */
	file: string;
	scope: Scope;
	facts: ProjectFacts;
}

export interface RuleResult {
	findings: Finding[];
	recommendations: Recommendation[];
}

export interface Assessment {
	ruleId: string;
	setting: string;
	risk: Level;
	riskReason: string;
	convenience: Level;
	convenienceReason: string;
	suggestion?: Suggestion;
}

export function toFinding(agent: Agent, file: string, a: Assessment): Finding {
	return { agent, file, ...a, verdict: decideVerdict(a.risk, a.convenience) };
}

export function isObj(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function get(root: unknown, path: string[]): unknown {
	let cur = root;
	for (const key of path) {
		if (!isObj(cur)) return undefined;
		cur = cur[key];
	}
	return cur;
}

export function stringArray(value: unknown): string[] {
	return Array.isArray(value)
		? value.filter((v): v is string => typeof v === "string")
		: [];
}
