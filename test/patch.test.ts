import { describe, expect, it } from "vitest";
import { applyPatches } from "../src/patch.js";

describe("applyPatches", () => {
	it("returns a patched copy without mutating the original", () => {
		const original = { permissions: { allow: ["Bash(*)", "Bash(ls *)"] } };
		const result = applyPatches(original, [
			{
				op: "remove-from-array",
				path: ["permissions", "allow"],
				values: ["Bash(*)"],
			},
			{
				op: "add-to-array",
				path: ["permissions", "deny"],
				values: ["Read(./.env)"],
			},
		]);
		expect(result).toEqual({
			permissions: { allow: ["Bash(ls *)"], deny: ["Read(./.env)"] },
		});
		expect(original.permissions.allow).toEqual(["Bash(*)", "Bash(ls *)"]);
	});

	it("add-to-array does not add duplicates", () => {
		const result = applyPatches({ a: ["x"] }, [
			{ op: "add-to-array", path: ["a"], values: ["x", "y"] },
		]);
		expect(result).toEqual({ a: ["x", "y"] });
	});

	it("set creates intermediate objects and delete removes the key", () => {
		const result = applyPatches({ sandbox_mode: "danger-full-access" }, [
			{ op: "delete", path: ["sandbox_mode"] },
			{
				op: "set",
				path: ["permissions", "project", "extends"],
				value: ":workspace",
			},
		]);
		expect(result).toEqual({
			permissions: { project: { extends: ":workspace" } },
		});
	});

	it("removes the key when its array becomes empty", () => {
		const result = applyPatches({ permissions: { allow: ["Bash(*)"] } }, [
			{
				op: "remove-from-array",
				path: ["permissions", "allow"],
				values: ["Bash(*)"],
			},
		]);
		expect(result).toEqual({ permissions: {} });
	});

	it("does not create missing levels for a delete", () => {
		const result = applyPatches({ a: 1 }, [
			{ op: "delete", path: ["x", "y", "z"] },
			{ op: "remove-from-array", path: ["p", "q"], values: ["v"] },
		]);
		expect(result).toEqual({ a: 1 });
	});
});
