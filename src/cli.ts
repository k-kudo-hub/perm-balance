#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { renderText, summarize } from "./render.js";
import { scan } from "./scan.js";

const USAGE = `使い方: perm-balance [ディレクトリ] [オプション]

AI エージェント（Claude Code・Codex）の権限設定を、リスクと利便性のバランスで点検します。
ディレクトリを省くと、いまのディレクトリを点検します。

点検するファイル:
  <ディレクトリ>/.claude/settings.json, .claude/settings.local.json, .codex/config.toml
  --user を付けると ~/.claude/settings.json と ~/.codex/config.toml も

オプション:
  --user            ユーザー全体の設定も点検する
  --file <パス>     このファイルも点検する（.toml は Codex、それ以外は Claude Code として読む）。何度でも指定できる
  --json            結果を JSON で出す
  --no-proposal     狭めた設定案を表示しない
  -h, --help        この使い方を表示する

終了コード:
  0  採用しない・狭めるの指摘がない
  1  採用しない・狭めるの指摘がある
  2  オプションの誤り、または読めない設定ファイルがある
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
		io.stderr(`ディレクトリは1つだけ指定できます\n\n${USAGE}`);
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
		io.stdout(renderText(reports, !values["no-proposal"]));
	}
	const errors = reports.filter((r) => r.error);
	for (const r of errors)
		io.stderr(`読めませんでした: ${r.file}: ${r.error}\n`);
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
