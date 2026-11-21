#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { renderText, summarize } from "./render.js";
import { scan } from "./scan.js";

const USAGE = `Usage: perm-balance [directory] [options]

Checks the permission settings of AI agents (Claude Code, Codex) by balancing risk and convenience.
Without a directory, checks the current directory.

Files checked:
  <directory>/.claude/settings.json, .claude/settings.local.json, .codex/config.toml
  with --user, also ~/.claude/settings.json and ~/.codex/config.toml

Options:
  --user            Also check user-wide settings
  --file <path>     Also check this file (.toml is read as Codex, anything else as Claude Code). Repeatable
  --json            Print the result as JSON
  --no-proposal     Do not print the narrowed proposal
  --full-proposal   Print the whole proposed file, not just the parts that change
  -h, --help        Show this help

Exit codes:
  0  No reject or narrow findings
  1  At least one reject or narrow finding
  2  Invalid options, or a settings file could not be read
`;

export interface Io {
	cwd: string;
	home: string;
	stdout: (text: string) => void;
	stderr: (text: string) => void;
}

export function main(argv: string[], io: Io): number {
	let parsed: ReturnType<typeof parseOptions>;
	try {
		parsed = parseOptions(argv);
	} catch (e) {
		io.stderr(`${e instanceof Error ? e.message : String(e)}\n\n${USAGE}`);
		return 2;
	}
	const { values, positionals } = parsed;
	if (values.help) {
		io.stdout(USAGE);
		return 0;
	}
	if (positionals.length > 1) {
		io.stderr(`Only one directory can be given\n\n${USAGE}`);
		return 2;
	}
	const root = resolve(io.cwd, positionals[0] ?? ".");
	const reports = scan({
		root,
		home: io.home,
		includeUser: values.user ?? false,
		files: (values.file ?? []).map((f) => resolve(io.cwd, f)),
	});

	const summary = summarize(reports);
	if (values.json) {
		io.stdout(`${JSON.stringify({ files: reports, summary }, null, 2)}\n`);
	} else {
		const mode = values["no-proposal"]
			? "none"
			: values["full-proposal"]
				? "full"
				: "changes";
		io.stdout(renderText(reports, mode));
	}
	const errors = reports.filter((r) => r.error);
	for (const r of errors) io.stderr(`Could not read: ${r.file}: ${r.error}\n`);
	if (errors.length > 0) return 2;
	return summary.reject + summary.narrow > 0 ? 1 : 0;
}

function parseOptions(argv: string[]) {
	return parseArgs({
		args: argv,
		allowPositionals: true,
		options: {
			user: { type: "boolean" },
			file: { type: "string", multiple: true },
			json: { type: "boolean" },
			"no-proposal": { type: "boolean" },
			"full-proposal": { type: "boolean" },
			help: { type: "boolean", short: "h" },
		},
	});
}

function isEntryPoint(): boolean {
	const entry = process.argv[1];
	if (!entry) return false;
	try {
		return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
	} catch {
		return false;
	}
}

if (isEntryPoint()) {
	process.exitCode = main(process.argv.slice(2), {
		cwd: process.cwd(),
		home: homedir(),
		stdout: (s) => process.stdout.write(s),
		stderr: (s) => process.stderr.write(s),
	});
}
