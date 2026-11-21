/** 3段階の度合い。リスクと利便性の両方に使う */
export type Level = "low" | "medium" | "high";

/**
 * 判定。著者の主張「最小から渡す。ただし最終的にはリスクと利便性のバランスで決める」に沿って、
 * リスクと利便性の組み合わせから決まる（`decideVerdict`）。
 */
export type Verdict = "reject" | "narrow" | "keep";

export type Agent = "claude-code" | "codex";

/** 設定ファイルの持ち主。ユーザー全体の設定か、プロジェクトの設定か */
export type Scope = "user" | "project";

/** 設定オブジェクトへの変更。狭めた設定案を作るのに使う */
export type Patch =
	| { op: "set"; path: string[]; value: unknown }
	| { op: "delete"; path: string[] }
	| { op: "add-to-array"; path: string[]; values: unknown[] }
	| { op: "remove-from-array"; path: string[]; values: unknown[] };

export interface Suggestion {
	/** 何をどう変えるかの説明 */
	summary: string;
	/** 設定案に反映する変更。説明だけで自動の変更がないときは空 */
	patches: Patch[];
}

export interface Finding {
	ruleId: string;
	agent: Agent;
	file: string;
	/** 指摘した設定（例: `permissions.allow: "Bash(*)"`） */
	setting: string;
	risk: Level;
	riskReason: string;
	convenience: Level;
	convenienceReason: string;
	verdict: Verdict;
	suggestion?: Suggestion;
}

/** 利便性をほとんど損なわずにリスクを下げられる、足すとよい設定 */
export interface Recommendation {
	ruleId: string;
	agent: Agent;
	file: string;
	summary: string;
	reason: string;
	patches: Patch[];
}

export interface FileReport {
	file: string;
	agent: Agent;
	scope: Scope;
	findings: Finding[];
	recommendations: Recommendation[];
	/** 指摘と推奨をすべて反映した設定案。変更がなければ undefined */
	proposal?: string;
	/** 設定案のうち、変わるトップレベルのキーだけを抜き出したもの */
	proposalChanges?: string;
	/** 設定案で消えるトップレベルのキー */
	removedKeys?: string[];
	/** 読めなかったときの理由 */
	error?: string;
}
