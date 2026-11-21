import { describe, expect, it } from "vitest";
import { decideVerdict } from "../src/verdict.js";

describe("decideVerdict", () => {
	it("リスクが小さければ、利便性によらず許可してよい", () => {
		expect(decideVerdict("low", "high")).toBe("keep");
		expect(decideVerdict("low", "low")).toBe("keep");
	});

	it("リスクがあって利便性が小さければ採用しない", () => {
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
