/** A three-step level, used for both risk and convenience */
export type Level = "low" | "medium" | "high";

/**
 * The verdict. Following the author's position (start from the least privilege, but in the end decide by balancing risk and convenience),
 * it is decided from the combination of risk and convenience (`decideVerdict`).
 */
export type Verdict = "reject" | "narrow" | "keep";

export type Agent = "claude-code" | "codex";

/** Who owns the settings file: user-wide or the project */
export type Scope = "user" | "project";

/** A change to a settings object, used to build the narrowed proposal */
export type Patch =
	| { op: "set"; path: string[]; value: unknown }
	| { op: "delete"; path: string[] }
	| { op: "add-to-array"; path: string[]; values: unknown[] }
	| { op: "remove-from-array"; path: string[]; values: unknown[] };

export interface Suggestion {
	/** What to change and how */
	summary: string;
	/** Changes applied to the proposal. Empty when there is only advice */
	patches: Patch[];
}

export interface Finding {
	ruleId: string;
	agent: Agent;
	file: string;
	/** The flagged setting (e.g. `permissions.allow: "Bash(*)"`) */
	setting: string;
	risk: Level;
	riskReason: string;
	convenience: Level;
	convenienceReason: string;
	verdict: Verdict;
	suggestion?: Suggestion;
}

/** A change worth adding: it lowers risk at almost no cost to convenience */
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
	/** The proposal with every finding and recommendation applied. undefined when nothing changes */
	proposal?: string;
	/** Only the top-level keys of the proposal that change */
	proposalChanges?: string;
	/** Top-level keys the proposal removes */
	removedKeys?: string[];
	/** Why the file could not be read */
	error?: string;
}
