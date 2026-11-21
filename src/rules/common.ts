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
	/** 狭めた案をプロジェクトのファイル構成から作っている */
	usesFacts?: boolean;
}

/** ユーザー全体の設定はすべてのプロジェクトに効くため、プロジェクト固有の値を案に入れない */
export const USER_SCOPE_NOTE =
	"ユーザー全体の設定はすべてのプロジェクトに効くため、案にはプロジェクト固有のコマンド・宛先・書き込み先を入れていない。それらは各プロジェクトの設定で許可する";

export function toFinding(
	agent: Agent,
	ctx: RuleContext,
	a: Assessment,
): Finding {
	const { usesFacts, ...rest } = a;
	const suggestion =
		a.suggestion && usesFacts && ctx.scope === "user"
			? {
					...a.suggestion,
					summary: `${a.suggestion.summary}。${USER_SCOPE_NOTE}`,
				}
			: a.suggestion;
	return {
		agent,
		file: ctx.file,
		...rest,
		suggestion,
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
