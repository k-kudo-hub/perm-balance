import type { Patch } from "./types.js";

type Obj = Record<string, unknown>;

function isObj(value: unknown): value is Obj {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Walks to the parent of path, creating it if missing */
function parentOf(root: Obj, path: string[]): Obj {
	let cur = root;
	for (const key of path.slice(0, -1)) {
		const next = cur[key];
		if (!isObj(next)) cur[key] = {};
		cur = cur[key] as Obj;
	}
	return cur;
}

/** Returns a copy with the patches applied in order. The original is not modified */
export function applyPatches<T>(config: T, patches: Patch[]): T {
	const root = structuredClone(config) as Obj;
	for (const patch of patches) {
		const last = patch.path.at(-1);
		if (last === undefined) continue;
		// Adding nothing is a no-op; never create an empty array (an empty allow list can block everything)
		if (patch.op === "add-to-array" && patch.values.length === 0) continue;
		if (patch.op === "delete" || patch.op === "remove-from-array") {
			// Removals never create missing levels
			const existing = patch.path
				.slice(0, -1)
				.reduce<unknown>(
					(cur, key) => (isObj(cur) ? cur[key] : undefined),
					root,
				);
			if (!isObj(existing)) continue;
		}
		const parent = parentOf(root, patch.path);
		switch (patch.op) {
			case "set":
				parent[last] = patch.value;
				break;
			case "delete":
				delete parent[last];
				break;
			case "add-to-array": {
				const arr = Array.isArray(parent[last])
					? (parent[last] as unknown[])
					: [];
				for (const v of patch.values) if (!arr.includes(v)) arr.push(v);
				parent[last] = arr;
				break;
			}
			case "remove-from-array": {
				if (!Array.isArray(parent[last])) break;
				const rest = (parent[last] as unknown[]).filter(
					(v) => !patch.values.includes(v),
				);
				if (rest.length === 0) delete parent[last];
				else parent[last] = rest;
				break;
			}
		}
	}
	return root as T;
}
