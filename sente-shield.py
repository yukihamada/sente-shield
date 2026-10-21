#!/usr/bin/env python3
"""Sente Shield CLI — 防御の民主化ツール

使い方:
  python3 sente-shield.py keygen          # 交換鍵を発行（要親キーまたは管理者権限）
  python3 sente-shield.py run <command>   # 隔離環境でコマンド実行
  python3 sente-shield.py patterns        # ローカルパターン一覧
  python3 sente-shield.py share <file>    # パターンを共有サーバに投稿 (v0.3)
  python3 sente-shield.py verify          # 境界の検証
  python3 sente-shield.py revoke <key>    # キーを無効化（要管理者権限）
"""
import json
import sys
import os
import hashlib
import secrets
import time
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
PATTERNS_DIR = ROOT / "patterns" / "local"
KEY_FILE = ROOT / ".exchange-key"
KEYS_DB = ROOT / "keys.json"

def load_keys():
    if not KEYS_DB.exists():
        return {"keys": [], "admin_key": None}
    return json.loads(KEYS_DB.read_text())

def save_keys(data):
    KEYS_DB.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    KEYS_DB.chmod(0o600)

def keygen(parent_key=None, admin=False):
    """交換鍵を発行"""
    keys_data = load_keys()
    
    # 管理者キーが未設定の場合、初回のみ管理者キーを発行
    if keys_data["admin_key"] is None:
        if not admin:
            print("初回発行は管理者権限が必要です。")
            print("牧（@maki）まで連絡して管理者キーを取得してください。")
            return
        admin_key = secrets.token_urlsafe(32)
        keys_data["admin_key"] = hashlib.sha256(admin_key.encode()).hexdigest()
        save_keys(keys_data)
        print("管理者キーを発行しました:", admin_key)
        print("このキーは安全に保管してください。紛失すると再発行できません。")
        return
    
    # 親キーの検証
    if not parent_key:
        print("親キーが必要です。")
        print("使用法: python3 sente-shield.py keygen --parent <parent_key>")
        return
    
    parent_hash = hashlib.sha256(parent_key.encode()).hexdigest()
    parent_valid = False
    for k in keys_data["keys"]:
        if k["key_hash"] == parent_hash and not k["revoked"]:
            parent_valid = True
            break
    
    if not parent_valid and parent_hash != keys_data["admin_key"]:
        print("親キーが無効です。")
        return
    
    # 新しいキーを発行
    new_key = secrets.token_urlsafe(32)
    new_key_hash = hashlib.sha256(new_key.encode()).hexdigest()
    reporter_id = new_key_hash[:16]
    
    key_record = {
        "key_hash": new_key_hash,
        "issued_by": parent_hash,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 1).isoformat(),
        "revoked": False,
        "revoked_reason": None
    }
    
    keys_data["keys"].append(key_record)
    save_keys(keys_data)
    
    print("交換キーを発行しました:", new_key)
    print("投稿者ID:", reporter_id)
    print("有効期限:", key_record["expires_at"])
    print("\nこのキーは共有サーバへの投稿に使用します。")
    print("紛失しないよう保管してください。")

def revoke(key_to_revoke, admin_key):
    """キーを無効化（連鎖無効化）"""
    keys_data = load_keys()
    admin_hash = keys_data["admin_key"]
    
    if hashlib.sha256(admin_key.encode()).hexdigest() != admin_hash:
        print("管理者キーが無効です。")
        return
    
    revoke_hash = hashlib.sha256(key_to_revoke.encode()).hexdigest()
    
    # 対象キーを無効化
    revoked_count = 0
    for k in keys_data["keys"]:
        if k["key_hash"] == revoke_hash and not k["revoked"]:
            k["revoked"] = True
            k["revoked_reason"] = "abuse_detected"
            revoked_count += 1
            print(f"キーを無効化しました: {k['key_hash'][:16]}...")
            
            # 連鎖無効化: このキーから発行された子キーも無効化
            for child in keys_data["keys"]:
                if child["issued_by"] == revoke_hash and not child["revoked"]:
                    child["revoked"] = True
                    child["revoked_reason"] = "parent_revoked"
                    revoked_count += 1
                    print(f"子キーも無効化しました: {child['key_hash'][:16]}...")
            break
    
    if revoked_count == 0:
        print("対象のキーが見つかりませんでした。")
        return
    
    save_keys(keys_data)
    print(f"\n合計 {revoked_count} 個のキーを無効化しました。")

def run(command):
    """隔離環境でコマンドを実行"""
    sys.path.insert(0, str(ROOT))
    from boundary import Broker, Journal, run_job
    journal = Journal(ROOT / "journal" / "events.jsonl")
    with Broker(journal) as broker:
        result = run_job(command, ROOT / "jobs", journal, broker=broker, timeout=30)
        print(json.dumps(result, indent=2, ensure_ascii=False))

def patterns():
    """ローカルに記録されたパターンを表示"""
    PATTERNS_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(PATTERNS_DIR.glob("*.json"))
    if not files:
        print("記録されたパターンはありません")
        return
    for f in files:
        data = json.loads(f.read_text())
        print(f"{f.name}: {data.get('kind', 'unknown')} [{data.get('severity', '?')}] {data.get('observed_at', '')}")

def share(filepath):
    """パターンを共有サーバに投稿 (v0.3 実装予定)"""
    print("共有サーバは v0.3 で実装予定です")
    print("現在はローカル記録のみ対応しています")

def verify():
    """境界の検証を実行"""
    sys.path.insert(0, str(ROOT))
    import subprocess
    result = subprocess.run([sys.executable, "-m", "unittest", "-v", "test_boundary"],
                          capture_output=True, text=True, cwd=str(ROOT))
    print(result.stdout)
    print(result.stderr)
    return result.returncode == 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "keygen":
        parent = None
        admin = False
        for i, arg in enumerate(sys.argv):
            if arg == "--parent" and i + 1 < len(sys.argv):
                parent = sys.argv[i + 1]
            elif arg == "--admin":
                admin = True
        keygen(parent, admin)
    elif cmd == "run":
        if len(sys.argv) < 3:
            print("使い方: python3 sente-shield.py run <command>")
            sys.exit(1)
        run(" ".join(sys.argv[2:]))
    elif cmd == "patterns":
        patterns()
    elif cmd == "share":
        if len(sys.argv) < 3:
            print("使い方: python3 sente-shield.py share <file>")
            sys.exit(1)
        share(sys.argv[2])
    elif cmd == "verify":
        ok = verify()
        sys.exit(0 if ok else 1)
    elif cmd == "revoke":
        if len(sys.argv) < 4:
            print("使い方: python3 sente-shield.py revoke <key> --admin <admin_key>")
            sys.exit(1)
        key_to_revoke = sys.argv[2]
        admin_key = None
        for i, arg in enumerate(sys.argv):
            if arg == "--admin" and i + 1 < len(sys.argv):
                admin_key = sys.argv[i + 1]
        if not admin_key:
            print("--admin <admin_key> が必要です")
            sys.exit(1)
        revoke(key_to_revoke, admin_key)
    else:
        print(__doc__)
        sys.exit(1)
