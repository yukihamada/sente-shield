# 攻撃パターン交換プロトコル v0.1（招待制）

## 目的
自分の環境で観測した攻撃・異常のシグナルを、秘密を除いた形で共有し、全員の検知ルールに反映する。

**重要**: 攻撃者がパターンを悪用しないよう、共有は招待制です。信頼できる利用者のみが参加できます。

## 交換キー (Exchange Key)

### 発行
- 32バイトのランダムトークン
- **初回発行**: 牧（@maki）まで連絡して審査後に発行
- **再発行**: 発行された人は、新しい利用者にキーを発行することができます
- 発行記録はジャーナルに記録され、追跡可能です

### 構造
```json
{
  "key": "32-byte-random-token",
  "issued_by": "parent_key_hash",
  "issued_at": "2026-10-21T00:00:00Z",
  "expires_at": "2027-10-21T00:00:00Z",
  "revoked": false,
  "revoked_reason": null
}
```

### 匿名化
- 投稿者識別子は `sha256(key)[0:16]` のみ
- キー自体はサーバに送信しない

### 無効化（連鎖無効化）
- 不正があった場合、そのキーは無効化されます
- **さらに、そのキーを発行した親キーも無効化されます**
- これにより、悪意ある利用者のネットワーク全体を遮断します

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
- 悪意ある投稿は HMAC 署名 + レート制限 + スコアで抑制
- 不正利用時はキーと親キーを連鎖無効化

## サーバ API (v0.3 実装予定)

### 投稿（要キー）
```
POST /v1/patterns
Authorization: Bearer <exchange_key>
Content-Type: application/json

{
  "pattern": { ... },
  "signature": "hmac-sha256(pattern, exchange_key)"
}
```

### 購読（認証不要）
```
GET /v1/patterns?since=<timestamp>
```

### キー発行（要親キー）
```
POST /v1/keys
Authorization: Bearer <parent_key>
Content-Type: application/json

{
  "new_key_hash": "sha256(new_key)",
  "issued_to": "user_identifier"
}
```

### キー無効化（要管理者権限）
```
POST /v1/keys/<key_hash>/revoke
Authorization: Bearer <admin_key>
Content-Type: application/json

{
  "reason": "abuse_detected",
  "cascade": true
}
```
