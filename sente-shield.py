#!/usr/bin/env python3
"""Sente Shield CLI — 防御の民主化ツール

使い方:
  python3 sente-shield.py keygen          # 交換鍵を発行
  python3 sente-shield.py run <command>   # 隔離環境でコマンド実行
  python3 sente-shield.py patterns        # ローカルパターン一覧
  python3 sente-shield.py share <file>    # パターンを共有サーバに投稿 (v0.3)
  python3 sente-shield.py verify          # 境界の検証
"""
import json
import sys
import os
import hashlib
import secrets
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PATTERNS_DIR = ROOT / "patterns" / "local"
KEY_FILE = ROOT / ".exchange-key"

def keygen():
    """交換鍵を発行して保存"""
    if KEY_FILE.exists():
        print("既に鍵が存在します:", KEY_FILE)
        print("再発行する場合は削除してから実行してください")
        return
    key = secrets.token_urlsafe(32)
    KEY_FILE.write_text(key)
    KEY_FILE.chmod(0o600)
    reporter_id = hashlib.sha256(key.encode()).hexdigest()[:16]
    print("交換鍵を発行しました:", KEY_FILE)
    print("投稿者ID:", reporter_id)
    print("この鍵は共有サーバへの投稿に使用します。紛失しないよう保管してください。")

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
        keygen()
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
    else:
        print(__doc__)
        sys.exit(1)
