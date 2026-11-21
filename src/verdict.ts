import type { Level, Verdict } from "./types.js";

/**
 * リスクと利便性から判定を決める。
 *
 * - 利便性が小さい → 採用しない（reject）。最小から渡すので、役に立たない許可は渡さない
 * - リスクが小さく、利便性がある → 許可してよい（keep）
 * - リスクも利便性もある → 利便性を残したまま範囲を狭める（narrow）
 */
export function decideVerdict(risk: Level, convenience: Level): Verdict {
	if (convenience === "low") return "reject";
	if (risk === "low") return "keep";
	return "narrow";
}
