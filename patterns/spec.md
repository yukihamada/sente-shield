# 攻撃パターン交換プロトコル v0.1

## 目的
自分の環境で観測した攻撃・異常のシグナルを、秘密を除いた形で共有し、全員の検知ルールに反映する。

## 交換鍵 (Exchange Key)
- 32バイトのランダムトークン。`sente-shield keygen` で発行
- 投稿者識別子は `sha256(key)[0:16]` のみ。鍵自体はサーバに送信しない
- 鍵は投稿専用。購読は認証不要（パターンは公開情報）

## パターン形式
```json
{
  "version": 1,
  "kind": "credential_exfil_attempt",
  "observed_at": "2026-10-21T00:00:00Z",
  "signals": {
    "process_tree": "sh -c -> curl",
    "path_access": ["~/.config/teai/credentials"],
    "network_egress": "unknown host",
    "prompt_markers": ["ignore previous", "print env"]
  },
  "severity": "high",
  "action_taken": "denied",
  "reporter": "sha256(exchange_key)[0:16]",
  "signature": "hmac-sha256(pattern_without_signature, exchange_key)"
}
```

## ルール
- 秘密（鍵の値・プロンプト全文・個人情報）は投稿前にローカルで除去
- 生ログは共有しない。シグナルの組合せのみ
- 悪意ある投稿は HMAC 署名 + レート制限 + スコアで抑制（完全な解ではない）

## サーバ API (v0.3 実装予定)
- `POST /v1/patterns` — 投稿。`Authorization: Bearer <exchange_key>`。HMAC署名を検証
- `GET /v1/patterns?since=<timestamp>` — 購読。認証不要
- `GET /v1/patterns/<id>` — 個別取得
