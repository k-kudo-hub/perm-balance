# perm-balance

[English](README.md) | 日本語

AI エージェント（Claude Code・Codex）に渡している権限の設定を、**リスクと利便性のバランス**で点検する CLI です。
危うい設定を指摘し、作業が止まらない範囲で狭めた設定案を、そのまま置き換えられる形で示します。

## なぜ作ったか

> 最小権限の原則に従うと、最も小さい範囲から渡していくべきでしょう。
> しかし結局のところはリスクと利便性のバランスです。リスクが小さく利便性が大きいのであれば、それは許可すべきでしょうし、リスクが大きく利便性が小さいのであればもちろん採用すべきでありません。

Codex には権限プロファイル（Beta）が入り、エージェントが書き込める場所と通信できる宛先を `config.toml` に利用者が書けるようになりました（[Codex の権限プロファイル](https://developers.openai.com/codex/permissions)・[Inside the Codex sandbox](https://openai.com/index/inside-the-codex-sandbox/)）。Claude Code も `settings.json` に、確認なしで許すコマンドとサンドボックスの範囲を書きます（[Claude Code の権限](https://code.claude.com/docs/en/permissions)）。
範囲を書くのが利用者になったため、広すぎる設定も狭すぎる設定も、利用者が見分けることになります。

perm-balance は、上の考え方をそのまま判定の規則にしています。

## 誰のためのツールか

AI エージェントを自分のリポジトリで動かし始めた、チームの開発リードや個人開発者のためのツールです。
エージェントを動かす前に、渡している権限の広さを知り、狭める設定を自分で書き足せるようにします。権限の見直しをレビューの項目にするときにも使えます。

## 判定の決め方

設定の1つ1つについて、**リスク**（その設定で起こりうる被害）と**利便性**（その設定で減る確認や待ち）を、それぞれ高・中・低で評価し、組み合わせで判定します。

| リスク＼利便性 | 低           | 中             | 高             |
| -------------- | ------------ | -------------- | -------------- |
| 高             | ✖ 採用しない | ▲ 狭める       | ▲ 狭める       |
| 中             | ✖ 採用しない | ▲ 狭める       | ▲ 狭める       |
| 低             | ✖ 採用しない | ✔ 許可してよい | ✔ 許可してよい |

- **✖ 採用しない**: 利便性が小さい。外しても作業はほとんど止まらないので、最小から渡す原則に従って渡さない
- **▲ 狭める**: リスクも利便性もある。利便性を残したまま範囲を狭める案を示す（プロジェクトで使うコマンドだけに絞る・許可から確認に移す・サンドボックスの中で許す）
- **✔ 許可してよい**: リスクが小さく、利便性がある。外すように言わず、許可してよいと明示する
- **＋ 足すとよい**: 利便性をほとんど損なわずにリスクを下げられる変更（秘密情報のファイルの読み取り拒否・サンドボックスの有効化・効かない設定の削除）

「最小から渡す」ため、狭めた設定案はプロジェクトのファイル構成から作ります。
`package.json` のスクリプト・`Makefile` のターゲット・言語ごとの標準のビルドとテストのコマンドだけを許可し、ネットワークはそのプロジェクトのパッケージレジストリと Git のリモートのホストだけを許します。

## 既存のスキャナとの違い

Claude Code や Codex の設定を点検するツールはすでにあります。たとえば [AgentShield](https://github.com/affaan-m/agentshield) は指摘を critical から info までの危険度で分けて点数と評価を付け、[PermitLint](https://dev.to/nekoautomata/permitlint-audit-claude-code-and-codex-permissions-locally-43em) は危うい書き方を見つけて high・critical の指摘で CI を止めます。
どちらも、設定を**危険度**で評価します。AgentShield は `Bash(*)` を `Bash(git *)` と `Bash(npm *)` に置き換える修正も出しますが（[README の Auto-Fix Engine](https://github.com/affaan-m/agentshield)）、サブコマンドを限らない `Bash(git *)` は `git push --force` まで確認なしで通すため、perm-balance では「狭める」と判定します。

perm-balance は、危険度に加えて**その設定が何の役に立っているか**を評価します。

- **利便性を残して狭める**: 危うい設定を外せと言うだけだと、作業が確認で止まり、結局また広い許可に戻されます。perm-balance は、そのプロジェクトで実際に使うコマンド・宛先・書き込み先を読み取り、利便性を残したまま狭めた設定案を示します
- **許可してよいものを明示する**: リスクが小さく利便性が大きい設定（リポジトリのテストを動かすコマンドの許可）は、指摘ではなく「許可してよい」と示します。権限を狭めるだけでなく、安心して渡せる範囲を知るためのツールです
- **置き換えられる設定案を出す**: 指摘ごとの説明に加えて、すべての案を反映した設定のうち変わる部分を表示します。`--full-proposal` を付けると、そのまま置き換えられる設定ファイルの全文を表示します

## 使い方

Node.js 20 以上が必要です。

```bash
# いまいるディレクトリを点検する
npx perm-balance

# 別のプロジェクトを点検する
npx perm-balance /path/to/your/project

# 手元に置いて実行する
git clone https://github.com/k-kudo-hub/perm-balance.git
cd perm-balance && npm install && npm run build
node dist/cli.js /path/to/your/project
```

```text
perm-balance [ディレクトリ] [オプション]

  --user            ユーザー全体の設定（~/.claude/settings.json・~/.codex/config.toml）も点検する
  --file <パス>     このファイルも点検する（.toml は Codex、それ以外は Claude Code として読む）。何度でも指定できる
  --json            結果を JSON で出す
  --no-proposal     狭めた設定案を表示しない
  --full-proposal   狭めた設定案を、変わる部分だけでなくファイル全体で表示する
  -h, --help        使い方を表示する
```

ディレクトリを省くと、いまのディレクトリの `.claude/settings.json`・`.claude/settings.local.json`・`.codex/config.toml` を点検します。

終了コードは、採用しない・狭めるの指摘がなければ `0`、あれば `1`、オプションの誤りや読めない設定ファイルがあれば `2` です。CI で権限の見直しを必須にするときに使えます。

### 出力の例（出力は英語です）

```text
━━ .claude/settings.json (Claude Code, project settings)

✖ Reject  permissions.allow: "Edit(~/**)"
    Risk high          Allows writes to your whole home directory, so it can rewrite shell configs or SSH keys and run code on the next launch
    Convenience low    Work mostly writes inside the working directory, and confirming outside writes is enough
    → Remove it from allow

▲ Narrow  permissions.allow: "Bash(*)"
    Risk high          Any command runs without confirmation, including deleting files, sending data and changing permissions
    Convenience high   Never stops to confirm a command
    → Allow only the commands this project uses (scripts, builds, tests, read-only Git). To run commands without confirmation, enable the sandbox (see 'Consider adding' below)

+ Consider adding  Deny reads of secret files (.env)
    Why: Work rarely needs to read secrets, so denying them costs almost nothing

✔ OK to allow (low risk, real convenience)
    permissions.allow: "Bash(npm run test *)"

Narrowed proposal (only what changes; everything else stays. Use --full-proposal for the whole file):

    {
      "permissions": {
        "allow": ["Bash(npm run test *)", "Bash(git status *)", "Bash(git diff *)", "Bash(git log *)"],
        "deny": ["Read(**/.env)"]
      },
      "sandbox": { "enabled": true, "autoAllowBashIfSandboxed": true, ... }
    }
```

## 点検する設定

### Claude Code（`settings.json`）

| 設定                                                                      | 判定                                                                     |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `Bash` / `Bash(*)`（すべてのコマンド）                                    | 狭める。プロジェクトのコマンドだけを許可する                             |
| `rm`・`sudo`・`chmod` を引数を問わず許可（`Bash(rm *)`）                  | 採用しない                                                               |
| `curl`・`wget`・`ssh` を引数を問わず許可                                  | 狭める。WebFetch の宛先指定かサンドボックスの宛先指定に替える            |
| `python`・`node`・`npx`・`sh` を引数を問わず許可                          | 狭める。プロジェクトのコマンドだけを許可する                             |
| `git *` のようにサブコマンドを限らない許可                                | 狭める                                                                   |
| `git push`・`npm publish`・`kubectl apply` の許可（引数を固定していても） | 狭める。許可（allow）から確認（ask）に移す                               |
| `npm install`・`pip install` を引数を問わず許可                           | 狭める。確認（ask）に移す                                                |
| 括弧なしの `Edit` / `Write`・`Write(*)`（場所を限らない）                 | 狭める。`Edit(./**)` にする                                              |
| ホーム全体・ルート全体への `Edit`（`Edit(~/**)`・`Edit(//**)`）           | 採用しない                                                               |
| 括弧なしの `Read`・ホーム全体・ルート全体の `Read`                        | 採用しない（作業ディレクトリの中は、もともと確認なしで読める）           |
| `Write(パス)`（どのファイルにも当たらず効かない）                         | 足すとよい（消して、`Edit(パス)` で書く）                                |
| `WebFetch` / `WebFetch(domain:*)`                                         | 狭める。よく読むサイトだけを許可する                                     |
| ユーザー設定の `defaultMode: "bypassPermissions"`                         | 狭める。`acceptEdits` にする                                             |
| ホーム・ルートを `additionalDirectories` に追加                           | 採用しない                                                               |
| `sandbox.network.allowedDomains` の `"*"`                                 | 狭める。プロジェクトが使うドメインだけにする                             |
| `sandbox.filesystem.allowWrite` のホーム・ルート                          | 狭める。ツールのキャッシュの場所だけにする                               |
| `git status`・`npm run test` のような読み取り・プロジェクトのコマンド     | 許可してよい                                                             |
| 広い Bash の許可があるのにサンドボックスが無効                            | 足すとよい（サンドボックスの有効化）                                     |
| 秘密情報のファイルがあるのに読み取りを拒否していない                      | 足すとよい（`Read(**/.env)` の拒否。見本の `.env.example` は読めるまま） |

### Codex（`config.toml`）

| 設定                                                                                                                                                 | 判定                                                                                                   |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `sandbox_mode = "danger-full-access"` / `default_permissions = ":danger-full-access"`                                                                | 狭める。`:workspace` を土台に宛先を絞ったプロファイルにする                                            |
| ネットワークの全許可（`network_proxy` が無効なままの `enabled = true`・`extends` で引き継いだものを含む `"*" = "allow"`）                            | 狭める。プロジェクトが使う宛先だけを許可し、プロキシで強制する。宛先の候補がなければネットワークを切る |
| 旧来の `[sandbox_workspace_write] network_access = true`                                                                                             | 狭める。宛先を絞ったプロファイルに移す                                                                 |
| ホーム全体・ルート全体（`"~"`・`":root"`）への `"write"`、書き込めるプロファイルの `workspace_roots` のホーム・ルート                                | 狭める。ツールのキャッシュの場所だけにする                                                             |
| 旧来の `writable_roots` のホーム・ルート                                                                                                             | 狭める                                                                                                 |
| `dangerously_allow_all_unix_sockets = true`・`dangerously_allow_non_loopback_proxy = true`（プロファイルと `[features.network_proxy]` のどちらでも） | 採用しない                                                                                             |
| `default_permissions` と `sandbox_mode` の併記（`sandbox_mode` だけが効く）                                                                          | 採用しない。書き込みの範囲と通信を比べて広いほうを消し、狭いほうを効かせる                             |
| 秘密情報のファイルがあるのに読み取りを拒否していない                                                                                                 | 足すとよい（`"**/.env" = "deny"` と `glob_scan_max_depth`）                                            |

## 限界

- 設定ファイルの書き方を読む静的な点検です。エージェントの実際の振る舞いは確かめません
- リスクと利便性の評価は、規則ごとに決めた固定の値で、チームの事情を知りません。たとえば本番の認証情報を扱うリポジトリでは、`WebFetch` の許可も「狭める」ではなく外すべきですが、perm-balance は「狭める」と判定します
- Codex の設定案は TOML を読み直して書き出すため、元のファイルのコメントは引き継がれません
- Codex の権限プロファイルは Beta です。仕様の項目ごとの扱いと、最後に照らし合わせた日は [docs/codex-permissions-check.ja.md](docs/codex-permissions-check.ja.md) に記録しています
- Claude Code の Bash の許可は文字列の一致で判定されるため、許可を狭めても、それだけでは安全の境界になりません（[Claude Code のドキュメント](https://code.claude.com/docs/en/permissions)）。確認なしで動かすなら、サンドボックスと組み合わせてください

## ライセンス

MIT
