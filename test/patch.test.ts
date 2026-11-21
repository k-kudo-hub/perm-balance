import { describe, expect, it } from "vitest";
import { applyPatches } from "../src/patch.js";

describe("applyPatches", () => {
	it("元のオブジェクトを変えずに、変更を反映した複製を返す", () => {
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

	it("add-to-array は重複を足さない", () => {
		const result = applyPatches({ a: ["x"] }, [
			{ op: "add-to-array", path: ["a"], values: ["x", "y"] },
		]);
		expect(result).toEqual({ a: ["x", "y"] });
	});

	it("set は途中のオブジェクトを作り、delete はキーを消す", () => {
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

	it("空になった配列はキーごと消す", () => {
		const result = applyPatches({ permissions: { allow: ["Bash(*)"] } }, [
			{
				op: "remove-from-array",
				path: ["permissions", "allow"],
				values: ["Bash(*)"],
			},
		]);
		expect(result).toEqual({ permissions: {} });
	});
});
