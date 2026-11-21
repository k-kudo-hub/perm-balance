import { USER_SCOPE_NOTE } from "./rules/common.js";
import type { FileReport, Finding, Level, Verdict } from "./types.js";

/** 設定案の表示: 変わる部分だけ・ファイル全体・表示しない */
export type ProposalMode = "changes" | "full" | "none";

const LEVEL: Record<Level, string> = { high: "高", medium: "中", low: "低" };
const AGENT = { "claude-code": "Claude Code", codex: "Codex" } as const;
const SCOPE = {
	user: "ユーザー全体の設定",
	project: "プロジェクトの設定",
} as const;
const VERDICT_LABEL: Record<Verdict, string> = {
	reject: "✖ 採用しない",
	narrow: "▲ 狭める",
	keep: "✔ 許可してよい",
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
		`    リスク ${LEVEL[f.risk]}    ${f.riskReason}`,
		`    利便性 ${LEVEL[f.convenience]}    ${f.convenienceReason}`,
	];
	if (f.suggestion) lines.push(`    → ${f.suggestion.summary}`);
	return lines.join("\n");
}

function renderFile(report: FileReport, mode: ProposalMode): string {
	const out = [
		`━━ ${report.file}（${AGENT[report.agent]}・${SCOPE[report.scope]}）`,
		"",
	];
	if (report.error) {
		out.push(`読めませんでした: ${report.error}`, "");
		return out.join("\n");
	}
	if (
		report.scope === "user" &&
		(report.findings.length > 0 || report.recommendations.length > 0)
	) {
		out.push(`※ ${USER_SCOPE_NOTE}`, "");
	}
	const headerLines = out.length;
	const order: Verdict[] = ["reject", "narrow"];
	for (const verdict of order) {
		for (const f of report.findings.filter((x) => x.verdict === verdict))
			out.push(renderFinding(f), "");
	}
	for (const r of report.recommendations) {
		out.push(`＋ 足すとよい  ${r.summary}`, `    理由: ${r.reason}`, "");
	}
	const keep = report.findings.filter((f) => f.verdict === "keep");
	if (keep.length > 0) {
		out.push("✔ 許可してよい（リスクが小さく、利便性が大きい）");
		for (const f of keep) out.push(`    ${f.setting}`);
		out.push("");
	}
	if (out.length === headerLines) out.push("指摘はありません", "");
	if (mode === "full" && report.proposal) {
		const note =
			report.agent === "codex" ? "。TOML のコメントは引き継がれません" : "";
		out.push(
			`狭めた設定案（${report.file} をこの内容にする${note}）:`,
			"",
			indent(report.proposal, "    "),
			"",
		);
	} else if (mode === "changes" && report.proposal) {
		out.push(
			`狭めた設定案（変わる部分だけ。ほかの設定はそのまま。ファイル全体は --full-proposal で表示）:`,
			"",
		);
		if (report.proposalChanges)
			out.push(indent(report.proposalChanges, "    "), "");
		if (report.removedKeys && report.removedKeys.length > 0) {
			out.push(`    消す設定: ${report.removedKeys.join("・")}`, "");
		}
	}
	return out.join("\n");
}

export function renderText(reports: FileReport[], mode: ProposalMode): string {
	const header =
		"perm-balance: 権限は最小から渡し、リスクと利便性のバランスで判断します\n\n";
	if (reports.length === 0) {
		return `${header}点検する設定ファイルが見つかりません（.claude/settings.json・.claude/settings.local.json・.codex/config.toml）。ユーザー全体の設定を点検するには --user を付けてください。\n`;
	}
	const s = summarize(reports);
	const body = reports.map((r) => renderFile(r, mode)).join("\n");
	const footer = `━━ まとめ: 採用しない ${s.reject}件・狭める ${s.narrow}件・許可してよい ${s.keep}件・足すとよい ${s.recommendations}件\n`;
	return `${header}${body}\n${footer}`;
}
