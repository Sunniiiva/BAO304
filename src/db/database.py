from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

# SQL-skjemaet for databasen (tabeller + indekser)
# Viktig endring: commits har nå composite primary key (repo_url, sha)
# og patch/cve_commit refererer til commits via (repo_url, commit_sha)
SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cve (
  cve_id      TEXT PRIMARY KEY,
  description TEXT,
  published   TEXT,
  severity    TEXT,
  cvss_score  REAL,
  cve_title   TEXT,
  cwe         TEXT,
  state       TEXT
);

-- "commit" kan være et reservert SQL-ord, derfor bruker vi "commits"
-- Ny PK: (repo_url, sha) slik at samme sha i ulike repoer ikke kolliderer
CREATE TABLE IF NOT EXISTS commits (
  repo_url      TEXT NOT NULL,
  sha           TEXT NOT NULL,
  url           TEXT,
  message       TEXT,
  commit_date   TEXT,
  author        TEXT,
  authored_date TEXT,
  PRIMARY KEY (repo_url, sha)
);

-- En rad per fil som ble endret i en commit
-- Må ha både repo_url og commit_sha for å kunne referere til commits PK
CREATE TABLE IF NOT EXISTS patch (
  patch_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_url      TEXT NOT NULL,
  commit_sha    TEXT NOT NULL,
  file_path     TEXT NOT NULL,
  language      TEXT,
  added_lines   INTEGER,
  removed_lines INTEGER,
  hunk_count    INTEGER,
  diff_text     TEXT,
  FOREIGN KEY (repo_url, commit_sha)
    REFERENCES commits(repo_url, sha)
    ON DELETE CASCADE
);

-- Koblingstabell: mange CVE-er kan kobles til mange commits
-- Må ha både repo_url og commit_sha for å peke på riktig commit
CREATE TABLE IF NOT EXISTS cve_commit (
  cve_id     TEXT NOT NULL,
  repo_url   TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  method     TEXT,
  confidence REAL,
  PRIMARY KEY (cve_id, repo_url, commit_sha),
  FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE,
  FOREIGN KEY (repo_url, commit_sha)
    REFERENCES commits(repo_url, sha)
    ON DELETE CASCADE
);

-- Indekser for raskere oppslag når databasen blir større
CREATE INDEX IF NOT EXISTS idx_patch_repo_sha ON patch(repo_url, commit_sha);
CREATE INDEX IF NOT EXISTS idx_cve_commit_repo_sha ON cve_commit(repo_url, commit_sha);
CREATE INDEX IF NOT EXISTS idx_cve_commit_cve_id ON cve_commit(cve_id);
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
    cve_title: Optional[str] = None,
    cwe: Optional[str] = None,
    state: Optional[str] = None,
) -> None:
    """Legger inn CVE, eller oppdaterer hvis den finnes fra før."""
    conn.execute(
        """
        INSERT INTO cve(cve_id, description, published, severity, cvss_score, cve_title, cwe, state)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
          description=COALESCE(excluded.description, cve.description),
          published=COALESCE(excluded.published, cve.published),
          severity=COALESCE(excluded.severity, cve.severity),
          cvss_score=COALESCE(excluded.cvss_score, cve.cvss_score),
          cve_title=COALESCE(excluded.cve_title, cve.cve_title),
          cwe=COALESCE(excluded.cwe, cve.cwe),
          state=COALESCE(excluded.state, cve.state)
        """,
        (cve_id, description, published, severity, cvss_score, cve_title, cwe, state),
    )
    conn.commit()


def upsert_commit(
    conn: sqlite3.Connection,
    *,
    repo_url: str,
    sha: str,
    url: Optional[str] = None,
    message: Optional[str] = None,
    commit_date: Optional[str] = None,
    author: Optional[str] = None,
    authored_date: Optional[str] = None,
) -> None:
    """Legger inn commit, eller oppdaterer hvis den finnes fra før (unikt per repo_url+sha)."""
    if not repo_url:
        raise ValueError("repo_url must be provided for commits (composite primary key).")

    conn.execute(
        """
        INSERT INTO commits(repo_url, sha, url, message, commit_date, author, authored_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(repo_url, sha) DO UPDATE SET
          url=COALESCE(excluded.url, commits.url),
          message=COALESCE(excluded.message, commits.message),
          commit_date=COALESCE(excluded.commit_date, commits.commit_date),
          author=COALESCE(excluded.author, commits.author),
          authored_date=COALESCE(excluded.authored_date, commits.authored_date)
        """,
        (repo_url, sha, url, message, commit_date, author, authored_date),
    )
    conn.commit()


def insert_patch(
    conn: sqlite3.Connection,
    *,
    repo_url: str,
    commit_sha: str,
    file_path: str,
    language: Optional[str] = None,
    added_lines: Optional[int] = None,
    removed_lines: Optional[int] = None,
    hunk_count: Optional[int] = None,
    changed_lines: Optional[int] = None,
    diff_text: Optional[str] = None,
    before_code: Optional[str] = None,
    after_code: Optional[str] = None,
) -> int:
    """Legger inn en patch-rad (typisk per fil i en commit)."""
    if not repo_url:
        raise ValueError("repo_url must be provided for patch rows (FK to commits).")

    cur = conn.execute(
        """
        INSERT INTO patch(
          repo_url, commit_sha, file_path, language,
          added_lines, removed_lines, hunk_count, diff_text
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (repo_url, commit_sha, file_path, language, added_lines, removed_lines, hunk_count, diff_text),
    )
    conn.commit()
    return int(cur.lastrowid)


def link_cve_commit(
    conn: sqlite3.Connection,
    *,
    cve_id: str,
    repo_url: str,
    commit_sha: str,
    method: Optional[str] = None,
    confidence: Optional[float] = None,
) -> None:
    """Lager/oppdaterer kobling mellom en CVE og en commit."""
    if not repo_url:
        raise ValueError("repo_url must be provided for cve_commit links (FK to commits).")

    conn.execute(
        """
        INSERT INTO cve_commit(cve_id, repo_url, commit_sha, method, confidence)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cve_id, repo_url, commit_sha) DO UPDATE SET
          method=COALESCE(excluded.method, cve_commit.method),
          confidence=COALESCE(excluded.confidence, cve_commit.confidence)
        """,
        (cve_id, repo_url, commit_sha, method, confidence),
    )
    conn.commit()


def get_commits_for_cve(conn: sqlite3.Connection, cve_id: str):
    """Henter commits koblet til en CVE (nyttig for debugging/analyse)."""
    return conn.execute(
        """
        SELECT c.repo_url, c.sha, c.url, c.message, cc.method, cc.confidence
        FROM cve_commit cc
        JOIN commits c
          ON c.repo_url = cc.repo_url
         AND c.sha = cc.commit_sha
        WHERE cc.cve_id = ?
        ORDER BY cc.confidence DESC
        """,
        (cve_id,),
    ).fetchall()


def get_patches_for_commit(conn: sqlite3.Connection, repo_url: str, commit_sha: str):
    """Henter patch-rader (filendringer) for en commit."""
    return conn.execute(
        "SELECT * FROM patch WHERE repo_url = ? AND commit_sha = ?",
        (repo_url, commit_sha),
    ).fetchall()