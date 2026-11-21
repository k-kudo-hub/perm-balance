import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

export type Language = "node" | "python" | "rust" | "go";
export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

/** Facts read from the project's files, used to build proposals */
export interface ProjectFacts {
	root: string;
	languages: Language[];
	packageManager?: PackageManager;
	scripts: string[];
	makeTargets: string[];
	pythonTools: string[];
	secretFiles: string[];
	gitHosts: string[];
}

const LANGUAGE_ORDER: Language[] = ["node", "python", "rust", "go"];

function readText(path: string): string | undefined {
	try {
		return readFileSync(path, "utf8");
	} catch {
		return undefined;
	}
}

function detectPackageManager(root: string): PackageManager {
	if (existsSync(join(root, "pnpm-lock.yaml"))) return "pnpm";
	if (existsSync(join(root, "yarn.lock"))) return "yarn";
	if (existsSync(join(root, "bun.lock")) || existsSync(join(root, "bun.lockb")))
		return "bun";
	return "npm";
}

function readScripts(root: string): string[] {
	const text = readText(join(root, "package.json"));
	if (text === undefined) return [];
	try {
		const scripts = (JSON.parse(text) as { scripts?: Record<string, unknown> })
			.scripts;
		return scripts ? Object.keys(scripts) : [];
	} catch {
		return [];
	}
}

function readMakeTargets(root: string): string[] {
	const text = readText(join(root, "Makefile"));
	if (text === undefined) return [];
	const targets: string[] = [];
	for (const line of text.split("\n")) {
		// `name:` or `name: deps`, excluding assignments like `name := value` and special targets like `.PHONY`
		const m = /^([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*:(?![:=])/.exec(line);
		if (m?.[1] && !targets.includes(m[1])) targets.push(m[1]);
	}
	return targets;
}

const SKIP_DIRS = new Set([
	"node_modules",
	".git",
	"dist",
	"build",
	"vendor",
	"target",
	".venv",
]);
const SAMPLE_SUFFIXES = [".example", ".sample", ".template", ".dist"];

function isSecretName(name: string): boolean {
	if (name === ".env") return true;
	if (name.startsWith(".env."))
		return !SAMPLE_SUFFIXES.some((s) => name.endsWith(s));
	if (name.endsWith(".pem") || name.endsWith(".key")) return true;
	return ["id_rsa", "id_ed25519", "credentials.json"].includes(name);
}

/** How many path segments deep secret files are searched for (`.env`, `a/.env`, `a/b/.env`) */
export const SECRET_SCAN_DEPTH = 3;

/** Looks for secret-looking files up to SECRET_SCAN_DEPTH path segments deep */
function findSecretFiles(root: string, rel = "", depth = 0): string[] {
	if (depth >= SECRET_SCAN_DEPTH) return [];
	let entries: import("node:fs").Dirent[];
	try {
		entries = readdirSync(join(root, rel), { withFileTypes: true });
	} catch {
		return [];
	}
	const found: string[] = [];
	for (const entry of entries) {
		const path = rel ? `${rel}/${entry.name}` : entry.name;
		if (entry.isDirectory()) {
			if (!SKIP_DIRS.has(entry.name))
				found.push(...findSecretFiles(root, path, depth + 1));
		} else if (isSecretName(entry.name)) {
			found.push(path);
		}
	}
	return found;
}

function readGitHosts(root: string): string[] {
	let out: string;
	try {
		out = execFileSync(
			"git",
			["-C", root, "config", "--get-regexp", "^remote\\..*\\.url$"],
			{
				encoding: "utf8",
				stdio: ["ignore", "pipe", "ignore"],
			},
		);
	} catch {
		return [];
	}
	const hosts: string[] = [];
	for (const line of out.split("\n")) {
		const url = line.split(/\s+/)[1];
		if (!url) continue;
		// https://host/... / ssh://git@host/... / git@host:owner/repo
		const m = /^(?:[a-z+]+:\/\/)?(?:[^@/]+@)?([^/:]+)/.exec(url);
		if (m?.[1] && !hosts.includes(m[1])) hosts.push(m[1]);
	}
	return hosts;
}

/** Facts with nothing project-specific, used when checking user-wide settings */
export function emptyFacts(root: string): ProjectFacts {
	return {
		root,
		languages: [],
		scripts: [],
		makeTargets: [],
		pythonTools: [],
		secretFiles: [],
		gitHosts: [],
	};
}

export function readProjectFacts(root: string): ProjectFacts {
	const has = (name: string) => existsSync(join(root, name));
	const manifests: Record<Language, boolean> = {
		node: has("package.json"),
		python: has("pyproject.toml") || has("requirements.txt"),
		rust: has("Cargo.toml"),
		go: has("go.mod"),
	};
	const languages = LANGUAGE_ORDER.filter((lang) => manifests[lang]);
	const pyproject = readText(join(root, "pyproject.toml")) ?? "";
	return {
		root,
		languages,
		packageManager: languages.includes("node")
			? detectPackageManager(root)
			: undefined,
		scripts: readScripts(root),
		makeTargets: readMakeTargets(root),
		pythonTools: ["pytest", "ruff"].filter((tool) => pyproject.includes(tool)),
		secretFiles: findSecretFiles(root),
		gitHosts: readGitHosts(root),
	};
}

/**
 * Bash commands that are fine to allow.
 * Limiting them to scripts defined in the repository and each language's standard build and test commands
 * keeps the convenience of fewer confirmations without allowing arbitrary commands.
 */
export function allowCandidates(facts: ProjectFacts): string[] {
	const rules = ["Bash(git status *)", "Bash(git diff *)", "Bash(git log *)"];
	const pm = facts.packageManager;
	if (pm) for (const s of facts.scripts) rules.push(`Bash(${pm} run ${s} *)`);
	for (const t of facts.makeTargets) rules.push(`Bash(make ${t})`);
	const uv = existsSync(join(facts.root, "uv.lock")) ? "uv run " : "";
	if (facts.pythonTools.includes("pytest")) rules.push(`Bash(${uv}pytest *)`);
	if (facts.pythonTools.includes("ruff"))
		rules.push(`Bash(${uv}ruff check *)`, `Bash(${uv}ruff format *)`);
	if (facts.languages.includes("rust")) {
		for (const sub of ["build", "test", "check", "clippy", "fmt"])
			rules.push(`Bash(cargo ${sub} *)`);
	}
	if (facts.languages.includes("go")) {
		for (const sub of ["build", "test", "vet"]) rules.push(`Bash(go ${sub} *)`);
	}
	return rules;
}

const REGISTRIES: Record<Language, string[]> = {
	node: ["registry.npmjs.org"],
	python: ["pypi.org", "files.pythonhosted.org"],
	rust: ["crates.io", "index.crates.io", "static.crates.io"],
	go: ["proxy.golang.org", "sum.golang.org"],
};

/** Domains to allow instead of the whole network */
export function networkDomains(facts: ProjectFacts): string[] {
	const domains = facts.languages.flatMap((lang) => REGISTRIES[lang]);
	for (const host of facts.gitHosts)
		if (!domains.includes(host)) domains.push(host);
	return domains;
}

/** Paths to allow instead of the whole home directory (each tool's default cache or work directory) */
export function homeWriteCandidates(facts: ProjectFacts): string[] {
	const dirs: string[] = [];
	if (facts.packageManager === "npm") dirs.push("~/.npm");
	if (facts.languages.includes("rust")) dirs.push("~/.cargo");
	if (facts.languages.includes("go")) dirs.push("~/go");
	return dirs;
}

/**
 * Patterns (gitignore style) that deny reads of the secret files found.
 * A catch-all like `.env.*` would also block samples such as .env.example, so everything except keys (.pem, .key) is listed by file name
 */
export function secretDenyGlobs(facts: ProjectFacts): string[] {
	const names = [
		...new Set(facts.secretFiles.map((p) => p.split("/").at(-1) ?? p)),
	];
	const exact = names
		.filter((n) => !n.endsWith(".pem") && !n.endsWith(".key"))
		.sort()
		.map((n) => `**/${n}`);
	const keys = [".pem", ".key"]
		.filter((ext) => names.some((n) => n.endsWith(ext)))
		.map((ext) => `**/*${ext}`);
	return [...exact, ...keys];
}
