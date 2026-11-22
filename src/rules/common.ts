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
	/** File path for display */
	file: string;
	scope: Scope;
	facts: ProjectFacts;
	/**
	 * The other Codex config layer read together with this file: the user's ~/.codex/config.toml for the project's
	 * .codex/config.toml, and the reverse. Codex loads both, so a key in one can change what the other means
	 */
	codexLayer?: CodexLayer;
}

export interface CodexLayer {
	config: unknown;
	/** File path for display */
	file: string;
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

/** User-wide settings apply to every project, so proposals for them never include project-specific values */
export const USER_SCOPE_NOTE =
	"User-wide settings apply to every project, so the proposal leaves out project-specific commands, domains and write paths. Allow those in each project's own settings.";

export function toFinding(
	agent: Agent,
	ctx: RuleContext,
	a: Assessment,
): Finding {
	return {
		agent,
		file: ctx.file,
		...a,
		verdict: decideVerdict(a.risk, a.convenience),
	};
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
