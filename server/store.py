"""SQLite 기록 — 탐지 이벤트를 파일 하나에 쌓는다.

  events    탐지 이벤트. timestamp는 판단 근거가 된 패킷의 시각(pcap 재생이면 과거),
            received_at은 서버가 이벤트를 받은 실제 시각(epoch) — '지금 유효한 경보' 계산과 보관 기간에 쓴다
  state     작은 키-값 (예: 사용자가 '확인함'을 누른 마지막 이벤트 id)
"""
import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    module      TEXT NOT NULL,
    level       TEXT NOT NULL,
    title       TEXT NOT NULL,
    reason      TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    advice      TEXT NOT NULL,
    received_at REAL
);
CREATE INDEX IF NOT EXISTS idx_events_module ON events(module);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Store:
    def __init__(self, path, clock=time.time):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(events)")}
        if "received_at" not in cols:          # 이전 버전 DB
            self.db.execute("ALTER TABLE events ADD COLUMN received_at REAL")
        self.lock = threading.Lock()

    def add(self, ev):
        now = self.clock()
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO events (timestamp, module, level, title, reason, evidence, advice, received_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ev["timestamp"], ev["module"], ev["level"], ev["title"], ev["reason"],
                 json.dumps(ev["evidence"], ensure_ascii=False), json.dumps(ev["advice"], ensure_ascii=False), now))
            self.db.commit()
        return {"id": cur.lastrowid, **ev}

    def recent(self, limit=50, module=None, level=None, since=None):
        """최신순. since를 주면 그 id보다 새 이벤트만 (폴링용)."""
        sql, args = "SELECT * FROM events WHERE 1=1", []
        if since is not None:
            sql += " AND id > ?"
            args.append(int(since))
        if module:
            sql += " AND module = ?"
            args.append(module)
        if level:
            sql += " AND level = ?"
            args.append(level)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self.lock:
            rows = self.db.execute(sql, args).fetchall()
        return [self._row(r) for r in rows]

    def alerts_after(self, event_id, received_since):
        """'주의'·'경고' 중 id가 event_id보다 크고 received_since 이후에 받은 것 (재시작 때 유효 경보 복원용)."""
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM events WHERE id > ? AND received_at >= ? AND module != 'system' "
                "AND level IN ('caution', 'warning') ORDER BY id", (int(event_id), received_since)).fetchall()
        return [{**self._row(r), "received_at": r["received_at"]} for r in rows]

    def last_id(self):
        with self.lock:
            return self.db.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]

    def counts(self):
        with self.lock:
            rows = self.db.execute("SELECT level, COUNT(*) AS n FROM events GROUP BY level").fetchall()
        return {r["level"]: r["n"] for r in rows}

    def prune(self, keep_days):
        """keep_days일보다 오래된 이벤트를 지운다. 지운 개수를 돌려준다."""
        cutoff = self.clock() - keep_days * 86400
        with self.lock:
            # 이전 버전에서 쌓인 행(received_at 없음)은 언제 받았는지 모르므로 남겨 둔다
            cur = self.db.execute("DELETE FROM events WHERE received_at IS NOT NULL AND received_at < ?", (cutoff,))
            self.db.commit()
        return cur.rowcount

    def get(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def put(self, key, value):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)",
                            (key, json.dumps(value, ensure_ascii=False)))
            self.db.commit()

    @staticmethod
    def _row(r):
        d = dict(r)
        d.pop("received_at", None)
        return {**d, "evidence": json.loads(r["evidence"]), "advice": json.loads(r["advice"])}
