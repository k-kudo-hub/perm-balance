import type { Level, Verdict } from "./types.js";

/**
 * Decides the verdict from risk and convenience.
 *
 * - Low convenience → reject. Start from the least privilege: do not grant what does not help
 * - Low risk with some convenience → keep (OK to allow)
 * - Both risk and convenience → narrow the scope while keeping the convenience
 */
export function decideVerdict(risk: Level, convenience: Level): Verdict {
	if (convenience === "low") return "reject";
	if (risk === "low") return "keep";
	return "narrow";
}
