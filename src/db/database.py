from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

# SQL-skjemaet for databasen (tabeller + indekser)
SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cve (
  cve_id      TEXT PRIMARY KEY,
  description TEXT,
  published   TEXT,
  severity    TEXT,
  cvss_score  REAL
);

-- "commit" kan være et reservert SQL-ord, derfor bruker vi "commits"
CREATE TABLE IF NOT EXISTS commits (
  sha           TEXT PRIMARY KEY,
  url           TEXT,
  message       TEXT,
  commit_date   TEXT,
  author        TEXT,
  authored_date TEXT,
  repo_url      TEXT
);

-- En rad per fil som ble endret i en commit
CREATE TABLE IF NOT EXISTS patch (
  patch_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  commit_sha    TEXT NOT NULL,
  file_path     TEXT NOT NULL,
  language      TEXT,
  added_lines   INTEGER,
  removed_lines INTEGER,
  diff_text     TEXT,
  FOREIGN KEY (commit_sha) REFERENCES commits(sha) ON DELETE CASCADE
);

-- Koblingstabell: mange CVE-er kan kobles til mange commits
CREATE TABLE IF NOT EXISTS cve_commit (
  cve_id     TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  method     TEXT,
  confidence REAL,
  PRIMARY KEY (cve_id, commit_sha),
  FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE,
  FOREIGN KEY (commit_sha) REFERENCES commits(sha) ON DELETE CASCADE
);

-- Litt raskere oppslag når databasen blir større
CREATE INDEX IF NOT EXISTS idx_patch_commit_sha ON patch(commit_sha);
CREATE INDEX IF NOT EXISTS idx_cve_commit_sha ON cve_commit(commit_sha);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Åpner/laget sqlite-db på ønsket path og skrur på foreign keys."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row  # gjør at vi kan lese rader som dict-lignende
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Oppretter tabeller/indekser hvis de ikke finnes fra før."""
    conn.executescript(SCHEMA_SQL)
    conn.commit()


def upsert_cve(
    conn: sqlite3.Connection,
    *,
    cve_id: str,
    description: Optional[str] = None,
    published: Optional[str] = None,
    severity: Optional[str] = None,
    cvss_score: Optional[float] = None,
) -> None:
    """Legger inn CVE, eller oppdaterer hvis den finnes fra før."""
    conn.execute(
        """
        INSERT INTO cve(cve_id, description, published, severity, cvss_score)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
          description=COALESCE(excluded.description, cve.description),
          published=COALESCE(excluded.published, cve.published),
          severity=COALESCE(excluded.severity, cve.severity),
          cvss_score=COALESCE(excluded.cvss_score, cve.cvss_score)
        """,
        (cve_id, description, published, severity, cvss_score),
    )
    conn.commit()


def upsert_commit(
    conn: sqlite3.Connection,
    *,
    sha: str,
    url: Optional[str] = None,
    message: Optional[str] = None,
    commit_date: Optional[str] = None,
    author: Optional[str] = None,
    authored_date: Optional[str] = None,
    repo_url: Optional[str] = None,
) -> None:
    """Legger inn commit, eller oppdaterer hvis den finnes fra før."""
    conn.execute(
        """
        INSERT INTO commits(sha, url, message, commit_date, author, authored_date, repo_url)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sha) DO UPDATE SET
          url=COALESCE(excluded.url, commits.url),
          message=COALESCE(excluded.message, commits.message),
          commit_date=COALESCE(excluded.commit_date, commits.commit_date),
          author=COALESCE(excluded.author, commits.author),
          authored_date=COALESCE(excluded.authored_date, commits.authored_date),
          repo_url=COALESCE(excluded.repo_url, commits.repo_url)
        """,
        (sha, url, message, commit_date, author, authored_date, repo_url),
    )
    conn.commit()


def insert_patch(
    conn: sqlite3.Connection,
    *,
    commit_sha: str,
    file_path: str,
    language: Optional[str] = None,
    added_lines: Optional[int] = None,
    removed_lines: Optional[int] = None,
    diff_text: Optional[str] = None,
) -> int:
    """Legger inn en patch-rad (typisk per fil i en commit)."""
    cur = conn.execute(
        """
        INSERT INTO patch(commit_sha, file_path, language, added_lines, removed_lines, diff_text)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (commit_sha, file_path, language, added_lines, removed_lines, diff_text),
    )
    conn.commit()
    return int(cur.lastrowid)


def link_cve_commit(
    conn: sqlite3.Connection,
    *,
    cve_id: str,
    commit_sha: str,
    method: Optional[str] = None,
    confidence: Optional[float] = None,
) -> None:
    """Lager/oppdaterer kobling mellom en CVE og en commit."""
    conn.execute(
        """
        INSERT INTO cve_commit(cve_id, commit_sha, method, confidence)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(cve_id, commit_sha) DO UPDATE SET
          method=COALESCE(excluded.method, cve_commit.method),
          confidence=COALESCE(excluded.confidence, cve_commit.confidence)
        """,
        (cve_id, commit_sha, method, confidence),
    )
    conn.commit()


def get_commits_for_cve(conn: sqlite3.Connection, cve_id: str):
    """Henter commits koblet til en CVE (nyttig for debugging/analyse)."""
    return conn.execute(
        """
        SELECT c.sha, c.url, c.message, cc.method, cc.confidence
        FROM cve_commit cc
        JOIN commits c ON c.sha = cc.commit_sha
        WHERE cc.cve_id = ?
        ORDER BY cc.confidence DESC
        """,
        (cve_id,),
    ).fetchall()


def get_patches_for_commit(conn: sqlite3.Connection, commit_sha: str):
    """Henter patch-rader (filendringer) for en commit."""
    return conn.execute(
        "SELECT * FROM patch WHERE commit_sha = ?",
        (commit_sha,),
    ).fetchall()
