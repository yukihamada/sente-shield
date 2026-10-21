# Sente Shield 使い方

## 1. セットアップ

```sh
git clone https://github.com/yukihamada/sente-shield.git
cd sente-shield
python3 sente-shield.py verify   # 境界の検証（16テスト）
```

## 2. 交換鍵の発行（攻撃パターンを共有する場合）

```sh
python3 sente-shield.py keygen
```

- 鍵は `.exchange-key` に保存（chmod 600）
- 投稿者IDは `sha256(key)[0:16]` で匿名化
- 鍵は共有サーバへの投稿のみに使用。購読は不要

## 3. コマンドを隔離実行

```sh
python3 sente-shield.py run "echo hello"
```

- 専用ディレクトリで sandbox-exec により隔離実行
- ホーム・Keychain・他プロセス・直接ネットワークは拒否
- 外部APIアクセスはブローカー経由（短命ケイパビリティ）

## 4. 攻撃パターンの記録と共有

### ローカル記録
`patterns/local/` に JSON 形式で保存されます。

### 共有（v0.3 実装予定）
```sh
python3 sente-shield.py share patterns/local/2026-10-21-001.json
```

- 秘密（鍵の値・プロンプト全文・個人情報）は自動で除去
- HMAC-SHA256 署名で投稿者を検証
- レート制限とスコアで悪意ある投稿を抑制

## 5. 他の人のパターンを取得（v0.3 実装予定）

```sh
curl https://patterns.sente-shield.example/v1/patterns?since=2026-10-01
```

- 認証不要（パターンは公開情報）
- 取得したパターンは `rules.json` にマージされ、実行前の検知に使用

## 6. 設計と制限

詳細は [DESIGN.md](DESIGN.md) を参照してください。
- macOS `sandbox-exec` は非推奨API。本番は VM/コンテナ supervisor が必要
- リソース枯渇の包括制限は未実装
- パターン共有は Sybil 攻撃への耐性が限定的
