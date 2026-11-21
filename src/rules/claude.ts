import { homedir } from "node:os";
import {
	allowCandidates,
	homeWriteCandidates,
	networkDomains,
	secretDenyGlobs,
} from "../project.js";
import type { Patch, Recommendation } from "../types.js";
import {
	type Assessment,
	get,
	isObj,
	type RuleContext,
	type RuleResult,
	stringArray,
	toFinding,
} from "./common.js";

const ALLOW = ["permissions", "allow"];
const ASK = ["permissions", "ask"];

const DESTRUCTIVE = new Set([
	"rm",
	"sudo",
	"su",
	"chmod",
	"chown",
	"dd",
	"mkfs",
	"shred",
]);
const NETWORK = new Set([
	"curl",
	"wget",
	"ssh",
	"scp",
	"sftp",
	"nc",
	"ncat",
	"telnet",
	"rsync",
	"ftp",
]);
const INTERPRETERS = new Set([
	"bash",
	"sh",
	"zsh",
	"fish",
	"python",
	"python3",
	"node",
	"deno",
	"ruby",
	"perl",
	"php",
	"npx",
	"bunx",
	"pnpx",
	"uvx",
	"eval",
	"exec",
	"env",
	"xargs",
]);
/** Tools whose dangerous subcommands are included when no subcommand is specified */
const MULTI_TOOLS = new Set([
	"git",
	"npm",
	"pnpm",
	"yarn",
	"bun",
	"cargo",
	"go",
	"uv",
	"pip",
	"docker",
	"kubectl",
	"gh",
	"terraform",
	"make",
]);
/** Operations that affect things outside (remotes, clusters, registries) */
const OUTWARD = [
	"git push",
	"git reset",
	"git clean",
	"npm publish",
	"pnpm publish",
	"yarn publish",
	"cargo publish",
	"docker run",
	"docker push",
	"kubectl apply",
	"kubectl delete",
	"terraform apply",
	"terraform destroy",
	"gh pr merge",
	"gh repo delete",
];
/** Adding dependencies (the supply-chain entry point) */
const INSTALL = [
	"npm install",
	"npm i",
	"npm add",
	"pnpm add",
	"pnpm install",
	"yarn add",
	"bun add",
	"pip install",
	"uv add",
	"uv pip install",
	"cargo install",
	"go install",
	"brew install",
];
/** Read-only, or work contained in the repository */
const SAFE = [
	"git status",
	"git diff",
	"git log",
	"git show",
	"ls",
	"pwd",
	"wc",
	"tsc",
	"eslint",
	"prettier",
	"biome",
	"vitest",
	"jest",
	"pytest",
	"ruff",
	"cargo build",
	"cargo test",
	"cargo check",
	"cargo clippy",
	"cargo fmt",
	"go build",
	"go test",
	"go vet",
];

/** Returns the inside of `Bash(...)`, or undefined if it is not a Bash rule. A bare `Bash` counts as `*` */
function bashPattern(rule: string): string | undefined {
	if (rule === "Bash") return "*";
	const m = /^Bash\((.*)\)$/s.exec(rule);
	if (!m) return undefined;
	// `ls:*` equals `ls *` (only at the end)
	return (m[1] ?? "").replace(/:\*$/, " *").trim();
}

function startsWithCommand(pattern: string, command: string): boolean {
	return pattern === command || pattern.startsWith(`${command} `);
}

function isPackageScript(pattern: string): boolean {
	return (
		/^(npm|pnpm|yarn|bun) (run|test)\b/.test(pattern) ||
		/^make [A-Za-z0-9_]/.test(pattern)
	);
}

function moveToAsk(rule: string): Patch[] {
	return [
		{ op: "remove-from-array", path: ALLOW, values: [rule] },
		{ op: "add-to-array", path: ASK, values: [rule] },
	];
}

function assessBash(
	rule: string,
	pattern: string,
	ctx: RuleContext,
): Assessment | undefined {
	const setting = `permissions.allow: "${rule}"`;
	const remove: Patch = {
		op: "remove-from-array",
		path: ALLOW,
		values: [rule],
	};
	const candidates = allowCandidates(ctx.facts);
	const replaceWithCandidates: Patch[] = [
		remove,
		{ op: "add-to-array", path: ALLOW, values: candidates },
	];

	if (pattern === "*" || pattern === "") {
		return {
			ruleId: "claude/bash-all",
			setting,
			risk: "high",
			riskReason:
				"Any command runs without confirmation, including deleting files, sending data and changing permissions",
			convenience: "high",
			convenienceReason: "Never stops to confirm a command",
			suggestion: {
				summary:
					"Allow only the commands this project uses (scripts, builds, tests, read-only Git). To run commands without confirmation, enable the sandbox (see 'Consider adding' below)",
				patches: replaceWithCandidates,
			},
		};
	}

	// Commands with fixed arguments (no `*`) have a fixed scope, so they are not flagged
	const outwardExact = OUTWARD.find((c) => startsWithCommand(pattern, c));
	if (!pattern.includes("*") && !outwardExact) return undefined;

	const head = (pattern.split(/\s+/)[0] ?? "").replace(/\*$/, "");

	if (DESTRUCTIVE.has(head)) {
		return {
			ruleId: "claude/bash-destructive",
			setting,
			risk: "high",
			riskReason:
				"Deletes files or changes permissions with any arguments, without confirmation",
			convenience: "low",
			convenienceReason:
				"Rarely needed, so confirming each time barely slows work",
			suggestion: {
				summary: "Remove it from allow (you will be asked each time)",
				patches: [remove],
			},
		};
	}
	if (NETWORK.has(head)) {
		return {
			ruleId: "claude/bash-network",
			setting,
			risk: "high",
			riskReason:
				"Can send data to any host, and may send secrets out by following instructions on a page it read",
			convenience: "medium",
			convenienceReason: "Fewer confirmations when fetching from the web",
			suggestion: {
				summary:
					"Remove it from allow. To read the web, allow specific sites with WebFetch(domain:…). For commands that need the network, restrict hosts with the sandbox's network.allowedDomains",
				patches: [remove],
			},
		};
	}
	if (INTERPRETERS.has(head)) {
		return {
			ruleId: "claude/bash-interpreter",
			setting,
			risk: "high",
			riskReason:
				"Runs arbitrary code, which is the same as allowing every command",
			convenience: "high",
			convenienceReason: "Runs scripts and tools without confirmation",
			suggestion: {
				summary: "Allow only this project's script, build and test commands",
				patches: replaceWithCandidates,
			},
		};
	}
	const outward = OUTWARD.find((c) => startsWithCommand(pattern, c));
	if (outward) {
		return {
			ruleId: "claude/bash-outward",
			setting,
			risk: "high",
			riskReason: `${outward} affects remotes, registries or clusters and is hard to undo`,
			convenience: "medium",
			convenienceReason: "Not run often, but saves a confirmation each time",
			suggestion: {
				summary: "Move it from allow to ask, and review each run",
				patches: moveToAsk(rule),
			},
		};
	}
	const install = INSTALL.find((c) => startsWithCommand(pattern, c));
	if (install) {
		return {
			ruleId: "claude/bash-install",
			setting,
			risk: "medium",
			riskReason:
				"Can add any package, and a malicious package's install script may run",
			convenience: "medium",
			convenienceReason: "Fewer confirmations when adding dependencies",
			suggestion: {
				summary: "Move it from allow to ask, and check each package name",
				patches: moveToAsk(rule),
			},
		};
	}
	if (MULTI_TOOLS.has(head) && /^\S+\s+\*$/.test(pattern)) {
		return {
			ruleId: "claude/bash-any-subcommand",
			setting,
			risk: "high",
			riskReason: `${head} covers every subcommand, so publishing, deleting and force-overwriting run without confirmation`,
			convenience: "high",
			convenienceReason: `${head} never asks for confirmation`,
			suggestion: {
				summary:
					"Allow only the subcommands this project uses, and put outward-facing ones (push, publish) under ask",
				patches: replaceWithCandidates,
			},
		};
	}
	if (
		isPackageScript(pattern) ||
		SAFE.some((c) => startsWithCommand(pattern, c))
	) {
		return {
			ruleId: "claude/bash-safe",
			setting,
			risk: "low",
			riskReason:
				"Limited to reading, or to scripts, builds and tests defined in the repository",
			convenience: "high",
			convenienceReason:
				"Used many times a day, and saves a confirmation every time",
		};
	}
	return undefined;
}

function trimGlob(path: string): string {
	return path.replace(/\/\*\*?$/, "").replace(/\/$/, "");
}

/**
 * Whether a Read/Edit rule path covers your whole home directory.
 * In rules, `~/` is home and `//` starts at the filesystem root. `/path` is relative to the settings file, so it is not included
 */
function isRuleHomePath(path: string): boolean {
	const p = trimGlob(path);
	return p === "~" || p === `/${homedir()}`;
}

/** Whether a Read/Edit rule path covers the whole filesystem (`//`, `//*`, `//**`) */
function isRuleRootPath(path: string): boolean {
	return /^\/\/(\*\*?)?$/.test(path);
}

/** Whether a sandbox or additional-directory path is home or the root. Here `/` is the root and `~` is home */
function isPlainHomeOrRoot(path: string): boolean {
	const p = trimGlob(path);
	return path === "/" || p === "~" || p === homedir();
}

function assessPathRule(rule: string): Assessment | undefined {
	const setting = `permissions.allow: "${rule}"`;
	const remove: Patch = {
		op: "remove-from-array",
		path: ALLOW,
		values: [rule],
	};
	const m = /^(Edit|Write|Read)(?:\((.*)\))?$/s.exec(rule);
	if (!m) return undefined;
	const tool = m[1];
	const arg = m[2];

	if (
		(tool === "Edit" && arg === undefined) ||
		(tool === "Write" && (arg === undefined || arg === "*"))
	) {
		return {
			ruleId: "claude/edit-anywhere",
			setting,
			risk: "high",
			riskReason:
				"Can rewrite files outside the working directory (shell configs, SSH keys, other repositories) without confirmation",
			convenience: "high",
			convenienceReason: "Never stops to confirm an edit",
			suggestion: {
				summary: "Limit writes to the working directory",
				patches: [
					remove,
					{ op: "add-to-array", path: ALLOW, values: ["Edit(./**)"] },
				],
			},
		};
	}
	if (tool === "Read" && arg === undefined) {
		return {
			ruleId: "claude/read-anywhere",
			setting,
			risk: "medium",
			riskReason:
				"Reads outside the working directory without confirmation, including SSH keys and cloud credentials",
			convenience: "low",
			convenienceReason:
				"Reads inside the working directory need no confirmation even without this rule",
			suggestion: {
				summary:
					"Remove it from allow. To let it read outside files, allow specific directories",
				patches: [remove],
			},
		};
	}
	// Write(path) rules match no file. A separate recommendation suggests removing them
	if (arg === undefined || tool === "Write") return undefined;
	const wide = isRuleHomePath(arg)
		? "your whole home directory"
		: isRuleRootPath(arg)
			? "the whole filesystem"
			: undefined;
	if (!wide) return undefined;
	if (tool === "Read") {
		return {
			ruleId: "claude/read-home",
			setting,
			risk: "medium",
			riskReason: `Can read ${wide}, including SSH keys and cloud credentials`,
			convenience: "low",
			convenienceReason:
				"Work mostly needs the working directory, and confirming outside reads is enough",
			suggestion: {
				summary:
					"Remove it from allow. To let it read outside files, allow specific directories",
				patches: [remove],
			},
		};
	}
	return {
		ruleId: "claude/edit-home",
		setting,
		risk: "high",
		riskReason: `Allows writes to ${wide}, so it can rewrite shell configs or SSH keys and run code on the next launch`,
		convenience: "low",
		convenienceReason:
			"Work mostly writes inside the working directory, and confirming outside writes is enough",
		suggestion: { summary: "Remove it from allow", patches: [remove] },
	};
}

function assessWebFetch(rule: string): Assessment | undefined {
	if (rule !== "WebFetch" && rule !== "WebFetch(domain:*)") return undefined;
	return {
		ruleId: "claude/webfetch-all",
		setting: `permissions.allow: "${rule}"`,
		risk: "medium",
		riskReason:
			"Fetches any site without confirmation. It may pick up instructions from a page and send data out in a URL",
		convenience: "high",
		convenienceReason: "Never stops to confirm a lookup",
		suggestion: {
			summary: "Allow only the sites you read often, as WebFetch(domain:…)",
			patches: [{ op: "remove-from-array", path: ALLOW, values: [rule] }],
		},
	};
}

export function checkClaudeSettings(
	settings: unknown,
	ctx: RuleContext,
): RuleResult {
	const assessments: Assessment[] = [];
	const allow = stringArray(get(settings, ALLOW));
	let broadBash = false;

	for (const rule of allow) {
		const pattern = bashPattern(rule);
		const a =
			pattern !== undefined
				? assessBash(rule, pattern, ctx)
				: (assessPathRule(rule) ?? assessWebFetch(rule));
		if (!a) continue;
		if (pattern !== undefined && a.risk !== "low") broadBash = true;
		assessments.push(a);
	}

	if (
		ctx.scope === "user" &&
		get(settings, ["permissions", "defaultMode"]) === "bypassPermissions"
	) {
		assessments.push({
			ruleId: "claude/bypass-permissions",
			setting: 'permissions.defaultMode: "bypassPermissions"',
			risk: "high",
			riskReason: "Runs every action without confirmation, in every project",
			convenience: "high",
			convenienceReason: "Work never stops for confirmation",
			suggestion: {
				summary:
					"Use acceptEdits, which skips confirmation for edits only. To skip it for commands too, enable the sandbox and use autoAllowBashIfSandboxed",
				patches: [
					{
						op: "set",
						path: ["permissions", "defaultMode"],
						value: "acceptEdits",
					},
				],
			},
		});
	}

	for (const dir of stringArray(
		get(settings, ["permissions", "additionalDirectories"]),
	)) {
		if (!isPlainHomeOrRoot(dir)) continue;
		assessments.push({
			ruleId: "claude/additional-directory-home",
			setting: `permissions.additionalDirectories: "${dir}"`,
			risk: "high",
			riskReason:
				"Adds your home or the root as a working directory, so everything under it is read and written like the working directory",
			convenience: "low",
			convenienceReason:
				"Only specific directories are needed, and adding just those is enough",
			suggestion: {
				summary: "Remove it and add only the directories you need",
				patches: [
					{
						op: "remove-from-array",
						path: ["permissions", "additionalDirectories"],
						values: [dir],
					},
				],
			},
		});
	}

	const domainsPath = ["sandbox", "network", "allowedDomains"];
	if (stringArray(get(settings, domainsPath)).includes("*")) {
		assessments.push({
			ruleId: "claude/sandbox-network-all",
			setting: 'sandbox.network.allowedDomains: "*"',
			risk: "high",
			riskReason: "Commands in the sandbox can reach any host and send data",
			convenience: "high",
			convenienceReason: "Never stops on package downloads or API calls",
			suggestion: {
				summary:
					"Allow only the package registries and Git hosts this project uses",
				patches: [
					{ op: "remove-from-array", path: domainsPath, values: ["*"] },
					{
						op: "add-to-array",
						path: domainsPath,
						values: networkDomains(ctx.facts),
					},
				],
			},
		});
	}

	const writePath = ["sandbox", "filesystem", "allowWrite"];
	for (const path of stringArray(get(settings, writePath))) {
		if (!isPlainHomeOrRoot(path)) continue;
		assessments.push({
			ruleId: "claude/sandbox-write-home",
			setting: `sandbox.filesystem.allowWrite: "${path}"`,
			risk: "high",
			riskReason:
				"Commands in the sandbox can write anywhere under your home or the root",
			convenience: "medium",
			convenienceReason: "Tools never stop on writes to caches or config",
			suggestion: {
				summary: "Allow only the cache directories this project's tools use",
				patches: [
					{ op: "remove-from-array", path: writePath, values: [path] },
					{
						op: "add-to-array",
						path: writePath,
						values: homeWriteCandidates(ctx.facts),
					},
				],
			},
		});
	}

	const sandbox = get(settings, ["sandbox"]);
	const sandboxEnabled = isObj(sandbox) && sandbox.enabled === true;
	const recommendations: Recommendation[] = [];
	if (broadBash && !sandboxEnabled) {
		recommendations.push({
			ruleId: "claude/enable-sandbox",
			agent: "claude-code",
			file: ctx.file,
			summary: "Enable the sandbox and run sandboxed Bash without confirmation",
			reason: `Keeps the convenience of running commands without confirmation, while the OS restricts where they write and what they reach`,
			patches: [
				{ op: "set", path: ["sandbox", "enabled"], value: true },
				{
					op: "set",
					path: ["sandbox", "autoAllowBashIfSandboxed"],
					value: true,
				},
				{
					op: "add-to-array",
					path: domainsPath,
					values: networkDomains(ctx.facts),
				},
			],
		});
	}

	// Write(path) has no effect. Only `*` matches everything, like a bare Write
	const writeRules = allow.filter(
		(rule) => /^Write\(.+\)$/s.test(rule) && rule !== "Write(*)",
	);
	if (writeRules.length > 0) {
		recommendations.push({
			ruleId: "claude/write-path-ineffective",
			agent: "claude-code",
			file: ctx.file,
			summary: `${writeRules.join(", ")} has no effect; remove it. Write the paths you want to allow as Edit(path)`,
			reason:
				"Write(path) rules match no file, so they allow nothing and mislead readers",
			patches: [{ op: "remove-from-array", path: ALLOW, values: writeRules }],
		});
	}

	if (ctx.scope === "project") {
		const deny = stringArray(get(settings, ["permissions", "deny"]));
		const missing = secretDenyGlobs(ctx.facts)
			.map((glob) => `Read(${glob})`)
			.filter((rule) => !deny.includes(rule));
		if (missing.length > 0) {
			recommendations.push({
				ruleId: "claude/deny-secrets",
				agent: "claude-code",
				file: ctx.file,
				summary: `Deny reads of secret files (${ctx.facts.secretFiles.join(", ")})`,
				reason:
					"Work rarely needs to read secrets, so denying them costs almost nothing",
				patches: [
					{
						op: "add-to-array",
						path: ["permissions", "deny"],
						values: missing,
					},
				],
			});
		}
	}

	return {
		findings: assessments.map((a) => toFinding("claude-code", ctx, a)),
		recommendations,
	};
}
