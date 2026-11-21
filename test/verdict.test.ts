import { describe, expect, it } from "vitest";
import { decideVerdict } from "../src/verdict.js";

describe("decideVerdict", () => {
	it("allows when risk is low and there is convenience", () => {
		expect(decideVerdict("low", "high")).toBe("keep");
		expect(decideVerdict("low", "medium")).toBe("keep");
	});

	it("rejects when convenience is low regardless of risk (start from the minimum)", () => {
		expect(decideVerdict("low", "low")).toBe("reject");
		expect(decideVerdict("high", "low")).toBe("reject");
		expect(decideVerdict("medium", "low")).toBe("reject");
	});

	it("narrows while keeping convenience when there is both risk and convenience", () => {
		expect(decideVerdict("high", "high")).toBe("narrow");
		expect(decideVerdict("high", "medium")).toBe("narrow");
		expect(decideVerdict("medium", "medium")).toBe("narrow");
		expect(decideVerdict("medium", "high")).toBe("narrow");
	});
});
