import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

export type TrustLevel = "trusted" | "untrusted";

export interface CodexTrust {
	/** The saved decision. undefined when nothing is saved: Codex then does not load the project's .codex/ layer either */
	level: TrustLevel | undefined;
	/** The `projects.<key>` that holds the decision, or that Codex asks to trust when nothing is saved */
	key: string;
}

const DEFAULT_PROJECT_ROOT_MARKERS = [".git"];

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The canonical path first, then the path as given (Codex's normalized_project_trust_keys) */
function lookupKeys(path: string): string[] {
	let canonical = path;
	try {
		canonical = realpathSync(path);
	} catch {
		// Keep the path as given when it cannot be resolved
	}
	return canonical === path ? [path] : [canonical, path];
}

function ancestors(dir: string): string[] {
	const out = [dir];
	for (let d = dir; dirname(d) !== d; d = dirname(d)) out.push(dirname(d));
	return out;
}

/** A `.git` directory counts only with HEAD in it */
function isGitDir(dotGit: string): boolean {
	return existsSync(join(dotGit, "HEAD"));
}

function isDirectory(path: string): boolean {
	try {
		return lstatSync(path).isDirectory();
	} catch {
		return false;
	}
}

/** Codex's discover_project_root: the nearest ancestor with one of the markers */
function projectRoot(dir: string, markers: string[]): string | undefined {
	for (const ancestor of ancestors(dir)) {
		for (const marker of markers) {
			const path = join(ancestor, marker);
			if (!existsSync(path)) continue;
			if (marker === ".git" && isDirectory(path) && !isGitDir(path)) continue;
			return ancestor;
		}
	}
	return undefined;
}

/** Codex reads git metadata files only when they are regular files of at most 64 KiB (MAX_GIT_METADATA_FILE_BYTES) */
const MAX_GIT_METADATA_FILE_BYTES = 64 * 1024;

function readMetadataFile(path: string): string | undefined {
	try {
		const stat = lstatSync(path);
		if (!stat.isFile() || stat.size > MAX_GIT_METADATA_FILE_BYTES)
			return undefined;
		return readFileSync(path, "utf8").trim();
	} catch {
		return undefined;
	}
}

function readGitdirFile(dotGit: string): string | undefined {
	const contents = readMetadataFile(dotGit);
	if (contents === undefined || !contents.startsWith("gitdir:"))
		return undefined;
	const target = contents.slice("gitdir:".length).trim();
	return target === "" ? undefined : resolve(dirname(dotGit), target);
}

/**
 * Codex's resolve_root_git_project_for_trust: the nearest git checkout,
 * or its main checkout when it is a linked worktree
 */
function repoRootForTrust(dir: string): string | undefined {
	let root: string | undefined;
	for (const ancestor of ancestors(dir)) {
		const dotGit = join(ancestor, ".git");
		if (!existsSync(dotGit)) continue;
		if (isDirectory(dotGit) && !isGitDir(dotGit)) continue;
		root = ancestor;
		break;
	}
	if (root === undefined) return undefined;
	const dotGit = join(root, ".git");
	if (isDirectory(dotGit)) return root;

	const gitDir = readGitdirFile(dotGit);
	if (gitDir === undefined || !isDirectory(gitDir)) return undefined;
	try {
		const canonicalGitDir = realpathSync(gitDir);
		if (basename(dirname(canonicalGitDir)) !== "worktrees") return undefined;
		const commonDir = dirname(dirname(canonicalGitDir));
		// The worktree must be the one registered for this git dir, sharing its common dir
		const registeredDotGit = readMetadataFile(join(canonicalGitDir, "gitdir"));
		const commondir = readMetadataFile(join(canonicalGitDir, "commondir"));
		if (!registeredDotGit || !commondir) return undefined;
		const registered = resolve(canonicalGitDir, registeredDotGit);
		if (basename(registered) !== ".git") return undefined;
		if (
			realpathSync(dirname(registered)) !== realpathSync(root) ||
			realpathSync(resolve(canonicalGitDir, commondir)) !== commonDir
		)
			return undefined;
		const mainRoot = dirname(dirname(dirname(gitDir)));
		const mainDotGit = join(mainRoot, ".git");
		const mainGitDir = isDirectory(mainDotGit)
			? mainDotGit
			: readGitdirFile(mainDotGit);
		if (mainGitDir === undefined || realpathSync(mainGitDir) !== commonDir)
			return undefined;
		return mainRoot;
	} catch {
		return undefined;
	}
}

function savedLevels(userConfig: unknown): Map<string, TrustLevel> {
	const levels = new Map<string, TrustLevel>();
	const projects = isRecord(userConfig) ? userConfig.projects : undefined;
	if (!isRecord(projects)) return levels;
	for (const [key, project] of Object.entries(projects)) {
		const level = isRecord(project) ? project.trust_level : undefined;
		if (level === "trusted" || level === "untrusted") levels.set(key, level);
	}
	return levels;
}

/** undefined when the value is invalid: Codex then fails to load the config, so no trust is decided */
function markersOf(userConfig: unknown): string[] | undefined {
	const markers = isRecord(userConfig)
		? userConfig.project_root_markers
		: undefined;
	if (markers === undefined) return DEFAULT_PROJECT_ROOT_MARKERS;
	return Array.isArray(markers) &&
		markers.every((m): m is string => typeof m === "string")
		? markers
		: undefined;
}

/**
 * Whether Codex trusts the project whose .codex/ layer is in `dir`, read from the user's ~/.codex/config.toml.
 * Follows Codex's decision_for_dir: the directory itself, then the project root, then the git repository root
 * (the main checkout for a linked worktree). The first saved decision wins.
 * undefined when the config is one Codex refuses to load (an invalid project_root_markers).
 */
export function codexProjectTrust(
	userConfig: unknown,
	dir: string,
): CodexTrust | undefined {
	const levels = savedLevels(userConfig);
	const markers = markersOf(userConfig);
	if (markers === undefined) return undefined;
	const project = markers.length > 0 ? (projectRoot(dir, markers) ?? dir) : dir;
	const repo = repoRootForTrust(dir);
	const projectKeys = lookupKeys(project);
	const repoKeys = repo === undefined ? [] : lookupKeys(repo);
	for (const key of [...lookupKeys(dir), ...projectKeys, ...repoKeys]) {
		const level = levels.get(key);
		if (level !== undefined) return { level, key };
	}
	return { level: undefined, key: repoKeys[0] ?? (projectKeys[0] as string) };
}
