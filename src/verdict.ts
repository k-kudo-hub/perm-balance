import type { Level, Verdict } from "./types.js";

/**
 * リスクと利便性から判定を決める。
 *
 * - リスクが小さい → 許可してよい（keep）
 * - リスクがあるのに利便性が小さい → 採用しない（reject）
 * - リスクも利便性もある → 利便性を残したまま範囲を狭める（narrow）
 */
export function decideVerdict(risk: Level, convenience: Level): Verdict {
	if (risk === "low") return "keep";
	if (convenience === "low") return "reject";
	return "narrow";
}
