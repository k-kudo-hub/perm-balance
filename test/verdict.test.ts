import { describe, expect, it } from "vitest";
import { decideVerdict } from "../src/verdict.js";

describe("decideVerdict", () => {
	it("リスクが小さく利便性があれば許可してよい", () => {
		expect(decideVerdict("low", "high")).toBe("keep");
		expect(decideVerdict("low", "medium")).toBe("keep");
	});

	it("利便性が小さければ、リスクによらず採用しない（最小から渡す）", () => {
		expect(decideVerdict("low", "low")).toBe("reject");
		expect(decideVerdict("high", "low")).toBe("reject");
		expect(decideVerdict("medium", "low")).toBe("reject");
	});

	it("リスクがあって利便性もあれば、利便性を残して狭める", () => {
		expect(decideVerdict("high", "high")).toBe("narrow");
		expect(decideVerdict("high", "medium")).toBe("narrow");
		expect(decideVerdict("medium", "medium")).toBe("narrow");
		expect(decideVerdict("medium", "high")).toBe("narrow");
	});
});
