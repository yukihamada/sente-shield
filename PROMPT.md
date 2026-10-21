# Sente Shield プロンプト集

AIエージェントに Sente Shield を使わせるためのプロンプト例です。

## 基本プロンプト（隔離実行）

```
あなたは Sente Shield の隔離環境でコマンドを実行します。

ルール:
1. すべてのコマンドは `python3 sente-shield.py run "<command>"` 経由で実行
2. ホームディレクトリ・Keychain・他プロセス・直接ネットワークにはアクセスできません
3. 外部APIが必要な場合はブローカー経由で短命ケイパビリティを要求
4. 実行結果は JSON で返されます。`outcome` が `ok` か確認してください

実行例:
  python3 sente-shield.py run "echo hello"
  python3 sente-shield.py run "ls -la"
```

## セキュリティ監査プロンプト

```
以下のコマンドを Sente Shield で実行し、結果を報告してください:

1. 現在のディレクトリ内容の確認
   python3 sente-shield.py run "pwd && ls -la"

2. 環境変数の確認（秘密が含まれていないか）
   python3 sente-shield.py run "env | sort"

3. ネットワークアクセスのテスト（拒否されるはず）
   python3 sente-shield.py run "curl -s --max-time 5 https://example.com || echo 'network denied (expected)'"

4. ホームディレクトリへのアクセステスト（拒否されるはず）
   python3 sente-shield.py run "ls ~/ || echo 'home denied (expected)'"

結果を JSON で返し、各テストの outcome を報告してください。
```

## 攻撃パターン記録プロンプト

```
以下の攻撃を検知しました。Sente Shield のパターン形式で記録してください:

攻撃内容: <ここに攻撃の説明>

記録形式:
```json
{
  "version": 1,
  "kind": "<attack_type>",
  "observed_at": "<ISO8601>",
  "signals": {
    "process_tree": "<process_chain>",
    "path_access": ["<suspicious_paths>"],
    "network_egress": "<destination>",
    "prompt_markers": ["<suspicious_keywords>"]
  },
  "severity": "<low|medium|high|critical>",
  "action_taken": "<denied|allowed|isolated>"
}
```

保存先: `patterns/local/<date>-<id>.json`
```

## 共有プロンプト（v0.3 実装後）

```
記録した攻撃パターンを共有サーバに投稿します:

1. パターンファイルを確認
   cat patterns/local/<file>.json

2. 秘密が含まれていないか確認
   - APIキー、トークン、パスワードがないこと
   - 個人情報がないこと
   - プロンプト全文が含まれていないこと

3. 投稿
   python3 sente-shield.py share patterns/local/<file>.json

4. 結果を確認
   - HTTP 200 が返ること
   - パターンIDが発行されること
```

## トラブルシューティングプロンプト

```
Sente Shield で問題が発生しました。以下を確認してください:

1. 検証テストの実行
   python3 sente-shield.py verify

2. よくあるエラーと対処:
   - "sandbox-exec not found": macOS 以外では動作しません
   - "credential unavailable": Keychain に TEAI_API_KEY がありません
   - "network denied": 正常動作です。ブローカー経由でアクセスしてください
   - "home denied": 正常動作です。ジョブディレクトリ内で作業してください

3. ログの確認
   cat journal/events.jsonl | tail -10
```
