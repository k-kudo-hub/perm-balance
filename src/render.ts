import { USER_SCOPE_NOTE } from "./rules/common.js";
import type { FileReport, Finding, Level, Verdict } from "./types.js";

/** How to print the proposal: only what changes, the whole file, or not at all */
export type ProposalMode = "changes" | "full" | "none";

const LEVEL: Record<Level, string> = {
	high: "high",
	medium: "medium",
	low: "low",
};
const AGENT = { "claude-code": "Claude Code", codex: "Codex" } as const;
const SCOPE = {
	user: "user-wide settings",
	project: "project settings",
} as const;
const VERDICT_LABEL: Record<Verdict, string> = {
	reject: "✖ Reject",
	narrow: "▲ Narrow",
	keep: "✔ OK to allow",
};

export interface Summary {
	reject: number;
	narrow: number;
	keep: number;
	recommendations: number;
}

export function summarize(reports: FileReport[]): Summary {
	const findings = reports.flatMap((r) => r.findings);
	const count = (v: Verdict) => findings.filter((f) => f.verdict === v).length;
	return {
		reject: count("reject"),
		narrow: count("narrow"),
		keep: count("keep"),
		recommendations: reports.reduce((n, r) => n + r.recommendations.length, 0),
	};
}

function indent(text: string, prefix: string): string {
	return text
		.trimEnd()
		.split("\n")
		.map((line) => (line === "" ? "" : `${prefix}${line}`))
		.join("\n");
}

function renderFinding(f: Finding): string {
	const lines = [
		`${VERDICT_LABEL[f.verdict]}  ${f.setting}`,
		`    Risk ${LEVEL[f.risk].padEnd(6)}        ${f.riskReason}`,
		`    Convenience ${LEVEL[f.convenience].padEnd(6)} ${f.convenienceReason}`,
	];
	if (f.suggestion) lines.push(`    → ${f.suggestion.summary}`);
	return lines.join("\n");
}

function renderFile(report: FileReport, mode: ProposalMode): string {
	const out = [
		`━━ ${report.file} (${AGENT[report.agent]}, ${SCOPE[report.scope]})`,
		"",
	];
	if (report.error) {
		out.push(`Could not read: ${report.error}`, "");
		return out.join("\n");
	}
	if (report.notLoaded) {
		out.push(`Not checked: ${report.notLoaded}`, "");
		return out.join("\n");
	}
	if (report.note) out.push(`Note: ${report.note}`, "");
	if (
		report.scope === "user" &&
		(report.findings.length > 0 || report.recommendations.length > 0)
	) {
		out.push(`Note: ${USER_SCOPE_NOTE}`, "");
	}
	const headerLines = out.length;
	const order: Verdict[] = ["reject", "narrow"];
	for (const verdict of order) {
		for (const f of report.findings.filter((x) => x.verdict === verdict))
			out.push(renderFinding(f), "");
	}
	for (const r of report.recommendations) {
		out.push(`+ Consider adding  ${r.summary}`, `    Why: ${r.reason}`, "");
	}
	const keep = report.findings.filter((f) => f.verdict === "keep");
	if (keep.length > 0) {
		out.push("✔ OK to allow (low risk, real convenience)");
		for (const f of keep) out.push(`    ${f.setting}`);
		out.push("");
	}
	if (out.length === headerLines) out.push("No findings", "");
	if (mode === "full" && report.proposal) {
		const note =
			report.agent === "codex" ? ". TOML comments are not preserved" : "";
		out.push(
			`Narrowed proposal (replace ${report.file} with this${note}):`,
			"",
			indent(report.proposal, "    "),
			"",
		);
	} else if (mode === "changes" && report.proposal) {
		out.push(
			`Narrowed proposal (only what changes; everything else stays. Use --full-proposal for the whole file):`,
			"",
		);
		if (report.proposalChanges)
			out.push(indent(report.proposalChanges, "    "), "");
		if (report.removedKeys && report.removedKeys.length > 0) {
			out.push(`    Remove: ${report.removedKeys.join(", ")}`, "");
		}
	}
	return out.join("\n");
}

export function renderText(reports: FileReport[], mode: ProposalMode): string {
	const header =
		"perm-balance: start from the least privilege, then decide by balancing risk and convenience\n\n";
	if (reports.length === 0) {
		return `${header}No settings file found (.claude/settings.json, .claude/settings.local.json, .codex/config.toml). Add --user to check user-wide settings.\n`;
	}
	const s = summarize(reports);
	const body = reports.map((r) => renderFile(r, mode)).join("\n");
	const footer = `━━ Summary: ${s.reject} reject, ${s.narrow} narrow, ${s.keep} OK to allow, ${s.recommendations} consider adding\n`;
	return `${header}${body}\n${footer}`;
}
