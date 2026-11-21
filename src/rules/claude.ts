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
	USER_SCOPE_NOTE,
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
/** サブコマンドを限らずに許すと、危ういサブコマンドまで含んでしまうツール */
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
/** 外（リモート・クラスタ・公開先）に影響する操作 */
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
/** 依存の追加（サプライチェーンの入口） */
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
/** 読むだけか、リポジトリに閉じた作業 */
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

/** `Bash(...)` の中身を返す。Bash のルールでなければ undefined。`Bash` 単体は `*` とみなす */
function bashPattern(rule: string): string | undefined {
	if (rule === "Bash") return "*";
	const m = /^Bash\((.*)\)$/s.exec(rule);
	if (!m) return undefined;
	// `ls:*` は `ls *` と同じ（末尾だけ）
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
			usesFacts: true,
			setting,
			risk: "high",
			riskReason:
				"削除・送信・権限の変更を含む、どんなコマンドでも確認なしで実行できる",
			convenience: "high",
			convenienceReason: "コマンドのたびに確認で止まらずに済む",
			suggestion: {
				summary:
					"このプロジェクトで使うコマンド（スクリプト・ビルド・テスト・Git の読み取り）だけを許可する。確認なしで動かしたいなら、サンドボックスを有効にする（下の「足すとよい設定」）",
				patches: replaceWithCandidates,
			},
		};
	}

	// 引数を固定したコマンド（`*` を含まない）は範囲が決まっているので指摘しない
	if (!pattern.includes("*")) return undefined;

	const head = (pattern.split(/\s+/)[0] ?? "").replace(/\*$/, "");

	if (DESTRUCTIVE.has(head)) {
		return {
			ruleId: "claude/bash-destructive",
			setting,
			risk: "high",
			riskReason:
				"ファイルの削除や権限の変更を、引数を問わず確認なしで実行できる",
			convenience: "low",
			convenienceReason:
				"必要な場面は少なく、その都度確認しても作業はほとんど止まらない",
			suggestion: {
				summary: "許可から外す（実行するときに確認を求める）",
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
				"任意の宛先へデータを送れる。読み込んだページに書かれた指示に従って、秘密情報を外に送るおそれがある",
			convenience: "medium",
			convenienceReason: "Web の情報を取りに行く場面で確認が減る",
			suggestion: {
				summary:
					"許可から外す。Web を読むだけなら WebFetch(domain:…) で宛先を決めて許可し、コマンドに通信させたいならサンドボックスの network.allowedDomains で宛先を絞る",
				patches: [remove],
			},
		};
	}
	if (INTERPRETERS.has(head)) {
		return {
			ruleId: "claude/bash-interpreter",
			usesFacts: true,
			setting,
			risk: "high",
			riskReason:
				"任意のコードを実行できるため、すべてのコマンドを許可したのと変わらない",
			convenience: "high",
			convenienceReason: "スクリプトやツールを確認なしで動かせる",
			suggestion: {
				summary:
					"このプロジェクトのスクリプト・ビルド・テストのコマンドだけを許可する",
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
			riskReason: `${outward} はリモート・公開先・クラスタに影響し、取り消しにくい`,
			convenience: "medium",
			convenienceReason: "実行の回数は多くないが、毎回の確認の手間は減る",
			suggestion: {
				summary:
					"許可（allow）から確認（ask）に移し、実行のたびに内容を見て判断する",
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
				"任意のパッケージを追加でき、悪意あるパッケージのインストール時スクリプトが動くおそれがある",
			convenience: "medium",
			convenienceReason: "依存を足す場面で確認が減る",
			suggestion: {
				summary:
					"許可（allow）から確認（ask）に移し、追加するパッケージ名を見て判断する",
				patches: moveToAsk(rule),
			},
		};
	}
	if (MULTI_TOOLS.has(head) && /^\S+\s+\*$/.test(pattern)) {
		return {
			ruleId: "claude/bash-any-subcommand",
			usesFacts: true,
			setting,
			risk: "high",
			riskReason: `${head} のすべてのサブコマンドを含むため、公開・削除・強制上書きのような操作まで確認なしで実行できる`,
			convenience: "high",
			convenienceReason: `${head} を使うたびの確認がなくなる`,
			suggestion: {
				summary:
					"このプロジェクトで使うサブコマンドだけを許可し、外に影響するもの（push・publish）は確認（ask）に置く",
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
				"読み取りか、リポジトリに書かれたスクリプト・ビルド・テストに限られる",
			convenience: "high",
			convenienceReason: "日々の作業で何度も使い、毎回の確認がなくなる",
		};
	}
	return undefined;
}

function isHomePath(path: string): boolean {
	const home = homedir();
	const p = path.replace(/\/\*\*?$/, "").replace(/\/$/, "");
	return p === "~" || p === "$HOME" || p === home || p === `/${home}`;
}

function isRootPath(path: string): boolean {
	return /^\/\/?(\*\*?)?$/.test(path);
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

	if (tool !== "Read" && (arg === undefined || arg === "*" || arg === "**")) {
		return {
			ruleId: "claude/edit-anywhere",
			setting,
			risk: "high",
			riskReason:
				"作業ディレクトリの外（シェルの設定・SSH の鍵・ほかのリポジトリ）まで確認なしで書き換えられる",
			convenience: "high",
			convenienceReason: "編集のたびに確認で止まらずに済む",
			suggestion: {
				summary: "書き込みを作業ディレクトリの中に限る",
				patches: [
					remove,
					{ op: "add-to-array", path: ALLOW, values: ["Edit(./**)"] },
				],
			},
		};
	}
	if (tool === "Read" && (arg === undefined || arg === "*" || arg === "**")) {
		return {
			ruleId: "claude/read-anywhere",
			setting,
			risk: "medium",
			riskReason:
				"作業ディレクトリの外も確認なしで読めるため、SSH の鍵やクラウドの認証情報まで読み込める",
			convenience: "low",
			convenienceReason:
				"作業ディレクトリの中の読み取りは、この許可がなくても確認なしで行える",
			suggestion: {
				summary:
					"許可から外す。外のファイルを読ませたいときはディレクトリを個別に許可する",
				patches: [remove],
			},
		};
	}
	if (arg === undefined) return undefined;
	const wide = isHomePath(arg)
		? "ホーム全体"
		: isRootPath(arg)
			? "ファイルシステム全体"
			: undefined;
	if (!wide) return undefined;
	if (tool === "Read") {
		return {
			ruleId: "claude/read-home",
			setting,
			risk: "medium",
			riskReason: `${wide}を読めるため、SSH の鍵やクラウドの認証情報まで読み込める`,
			convenience: "low",
			convenienceReason:
				"作業に要るのは作業ディレクトリの中がほとんどで、外を読むのは都度の確認で足りる",
			suggestion: {
				summary:
					"許可から外す。外のファイルを読ませたいときはディレクトリを個別に許可する",
				patches: [remove],
			},
		};
	}
	return {
		ruleId: "claude/edit-home",
		setting,
		risk: "high",
		riskReason: `${wide}への書き込みを許すため、シェルの設定や SSH の鍵を書き換えて、次の起動時にコードを動かせる`,
		convenience: "low",
		convenienceReason:
			"作業に要る書き込みは作業ディレクトリの中がほとんどで、外への書き込みは都度の確認で足りる",
		suggestion: { summary: "許可から外す", patches: [remove] },
	};
}

function assessWebFetch(rule: string): Assessment | undefined {
	if (rule !== "WebFetch" && rule !== "WebFetch(domain:*)") return undefined;
	return {
		ruleId: "claude/webfetch-all",
		setting: `permissions.allow: "${rule}"`,
		risk: "medium",
		riskReason:
			"どのサイトでも確認なしで読み込む。読み込んだページに書かれた指示を取り込み、URL に載せて情報を送るおそれがある",
		convenience: "high",
		convenienceReason: "調べもののたびに確認で止まらずに済む",
		suggestion: {
			summary: "よく読むサイトだけを WebFetch(domain:…) の形で許可する",
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
			riskReason:
				"すべての操作を確認なしで実行する。すべてのプロジェクトに効く",
			convenience: "high",
			convenienceReason: "確認で作業が止まらない",
			suggestion: {
				summary:
					"編集だけを確認なしにする acceptEdits にする。コマンドも確認なしにしたいなら、サンドボックスを有効にして autoAllowBashIfSandboxed を使う",
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
		if (!isHomePath(dir) && dir !== "/") continue;
		assessments.push({
			ruleId: "claude/additional-directory-home",
			setting: `permissions.additionalDirectories: "${dir}"`,
			risk: "high",
			riskReason:
				"ホームかルートを作業ディレクトリに加えるため、その下のすべてを作業ディレクトリと同じ扱いで読み書きできる",
			convenience: "low",
			convenienceReason:
				"必要なのは特定のディレクトリで、それだけを加えれば足りる",
			suggestion: {
				summary: "外して、必要なディレクトリだけを加える",
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
			usesFacts: true,
			setting: 'sandbox.network.allowedDomains: "*"',
			risk: "high",
			riskReason:
				"サンドボックスの中のコマンドが、どこへでも通信してデータを送れる",
			convenience: "high",
			convenienceReason: "パッケージの取得や API の呼び出しで止まらない",
			suggestion: {
				summary:
					"このプロジェクトが使うパッケージレジストリと Git のホストだけを許可する",
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
		if (!isHomePath(path) && path !== "/") continue;
		assessments.push({
			ruleId: "claude/sandbox-write-home",
			usesFacts: true,
			setting: `sandbox.filesystem.allowWrite: "${path}"`,
			risk: "high",
			riskReason:
				"サンドボックスの中のコマンドが、ホームかルートの下のどこにでも書き込める",
			convenience: "medium",
			convenienceReason: "ツールのキャッシュや設定の書き込みで止まらない",
			suggestion: {
				summary: "このプロジェクトのツールが使うキャッシュの場所だけを許可する",
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
			summary:
				"サンドボックスを有効にし、サンドボックスの中の Bash は確認なしで実行する",
			reason: `コマンドを確認なしで動かす利便性を保ったまま、書き込み先とネットワークを OS の仕組みで制限できる${ctx.scope === "user" ? `。${USER_SCOPE_NOTE}` : ""}`,
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
				summary: `秘密情報のファイル（${ctx.facts.secretFiles.join("、")}）を読ませない`,
				reason:
					"作業で秘密情報を読む必要はほとんどなく、拒否しても利便性はほとんど落ちない",
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
