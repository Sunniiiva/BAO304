# --------------------------------------------------------------
# IMPORTS: impoterer biblitekene som trengs for DB-hånteringen
# ---------------------------------------------------------------
from __future__ import annotations

import sqlite3
from pathlib import Path


# -----------------
# Database schema
# -----------------
SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cve (
    cve_id TEXT PRIMARY KEY,
    title TEXT,
    published TEXT,
    severity TEXT,
    cvss_score REAL,
    cwe TEXT,
    state TEXT
);

CREATE TABLE IF NOT EXISTS cve_commit (
    cve_id TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    commit_url TEXT,
    method TEXT,
    confidence REAL,
    PRIMARY KEY (cve_id, repo_url, commit_sha),
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS commits (
    repo_url TEXT NOT NULL,
    sha TEXT NOT NULL,
    commit_url TEXT UNIQUE,
    commit_date TEXT,
    message TEXT,
    author TEXT,
    PRIMARY KEY (repo_url, sha)
);

CREATE TABLE IF NOT EXISTS patch (
    patch_id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_url TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    file_path TEXT NOT NULL,
    language TEXT,
    added_lines INTEGER,
    removed_lines INTEGER,
    hunk_count INTEGER,
    diff_text TEXT,
    before_code TEXT,
    after_code TEXT,
    FOREIGN KEY (repo_url, commit_sha) REFERENCES commits(repo_url, sha)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS functions (
  function_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_url        TEXT NOT NULL,
  commit_sha      TEXT NOT NULL,
  file_path       TEXT,
  method_name     TEXT,
  patched_start_line INTEGER,
  patched_end_line   INTEGER,
  vuln_start_line    INTEGER,
  vuln_end_line      INTEGER,
  vuln_function   TEXT,
  patch_function  TEXT,
  FOREIGN KEY (repo_url, commit_sha)
    REFERENCES commits(repo_url, sha)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sync_state (
    source_name TEXT PRIMARY KEY,
    release_tag TEXT,
    synced_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_patch_commit_file
ON patch(repo_url, commit_sha, file_path);

CREATE INDEX IF NOT EXISTS idx_cve_published
ON cve(published);

CREATE INDEX IF NOT EXISTS idx_cve_severity
ON cve(severity);

CREATE INDEX IF NOT EXISTS idx_cve_commit_cve_id
ON cve_commit(cve_id);

CREATE INDEX IF NOT EXISTS idx_cve_commit_repo_sha
ON cve_commit(repo_url, commit_sha);

CREATE INDEX IF NOT EXISTS idx_commits_commit_date
ON commits(commit_date);

CREATE INDEX IF NOT EXISTS idx_patch_repo_sha
ON patch(repo_url, commit_sha);

CREATE INDEX IF NOT EXISTS idx_functions_repo_sha
ON functions(repo_url, commit_sha);
"""


# -----------------------------------
# Funksjon for å koble til database
# -----------------------------------
def connect(db_path: str | Path) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA temp_store = MEMORY;")
    return conn


# -------------------------------------------------
# Funksjon for å initialisere database med schema
# -------------------------------------------------
def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()


# ---------------------------------------------------
# Funksjon for å oppdatere eller sette inn CVE-data
# ---------------------------------------------------
def upsert_cve(
    conn: sqlite3.Connection,
    cve_id: str,
    title: str | None = None,
    published: str | None = None,
    severity: str | None = None,
    cvss_score: float | None = None,
    cwe: str | None = None,
    state: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO cve (
            cve_id, title, published, severity, cvss_score, cwe, state
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            title = excluded.title,
            published = excluded.published,
            severity = excluded.severity,
            cvss_score = excluded.cvss_score,
            cwe = excluded.cwe,
            state = excluded.state
        """,
        (cve_id, title, published, severity, cvss_score, cwe, state),
    )


# ------------------------------------------------------
# Funksjon for å oppdatere eller sette inn commit data
# ------------------------------------------------------
def upsert_commit(
    conn: sqlite3.Connection,
    repo_url: str,
    sha: str,
    commit_url: str | None = None,
    message: str | None = None,
    commit_date: str | None = None,
    author: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO commits (
            repo_url, sha, commit_url, message, commit_date, author
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(repo_url, sha) DO UPDATE SET
            commit_url = COALESCE(excluded.commit_url, commits.commit_url),
            message = COALESCE(excluded.message, commits.message),
            commit_date = COALESCE(excluded.commit_date, commits.commit_date),
            author = COALESCE(excluded.author, commits.author)
        """,
        (repo_url, sha, commit_url, message, commit_date, author),
    )


# --------------------------------------------------------------------------------
# Funksjon for å oppdatere eller sette inn kobling mellom CVE-records til commits
# --------------------------------------------------------------------------------
def link_cve_commit(
    conn: sqlite3.Connection,
    cve_id: str,
    repo_url: str,
    commit_sha: str,
    commit_url: str | None = None,
    method: str | None = None,
    confidence: float | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO cve_commit (
            cve_id, repo_url, commit_sha, commit_url, method, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id, repo_url, commit_sha) DO UPDATE SET
            commit_url = COALESCE(excluded.commit_url, cve_commit.commit_url),
            method = COALESCE(excluded.method, cve_commit.method),
            confidence = COALESCE(excluded.confidence, cve_commit.confidence)
        """,
        (cve_id, repo_url, commit_sha, commit_url, method, confidence),
    )


# -----------------------------------------------------
# Funksjon for å oppdatere eller sette inn patch-data
# -----------------------------------------------------
def insert_patch(
    conn: sqlite3.Connection,
    repo_url: str,
    commit_sha: str,
    file_path: str,
    language: str | None = None,
    added_lines: int | None = None,
    removed_lines: int | None = None,
    hunk_count: int | None = None,
    diff_text: str | None = None,
    before_code: str | None = None,
    after_code: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO patch (
            repo_url,
            commit_sha,
            file_path,
            language,
            added_lines,
            removed_lines,
            hunk_count,
            diff_text,
            before_code,
            after_code
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(repo_url, commit_sha, file_path) DO UPDATE SET
            language = COALESCE(excluded.language, patch.language),
            added_lines = COALESCE(excluded.added_lines, patch.added_lines),
            removed_lines = COALESCE(excluded.removed_lines, patch.removed_lines),
            hunk_count = COALESCE(excluded.hunk_count, patch.hunk_count),
            diff_text = COALESCE(excluded.diff_text, patch.diff_text),
            before_code = COALESCE(excluded.before_code, patch.before_code),
            after_code = COALESCE(excluded.after_code, patch.after_code)
        """,
        (
            repo_url,
            commit_sha,
            file_path,
            language,
            added_lines,
            removed_lines,
            hunk_count,
            diff_text,
            before_code,
            after_code,
        ),
    )


# ---------------------------------------------
# Funksjon: Legger inn en funksjonsrad i DB
# ---------------------------------------------
def insert_function(
    conn: sqlite3.Connection,
    *,
    repo_url: str,
    commit_sha: str,
    file_path: str | None = None,
    method_name: str | None = None,
    patched_start_line: int | None = None,
    patched_end_line: int | None = None,
    vuln_start_line: int | None = None,
    vuln_end_line: int | None = None,
    vuln_function: str | None = None,
    patch_function: str | None = None,
) -> int:
    if not repo_url:
        raise ValueError("repo_url must be provided for function rows (FK to commits).")

    cur = conn.execute(
        """
        INSERT INTO functions(
          repo_url, commit_sha, file_path, method_name, patched_start_line, patched_end_line,
          vuln_start_line, vuln_end_line, vuln_function, patch_function
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            repo_url,
            commit_sha,
            file_path,
            method_name,
            patched_start_line,
            patched_end_line,
            vuln_start_line,
            vuln_end_line,
            vuln_function,
            patch_function,
        ),
    )
    return int(cur.lastrowid)


# -----------------------------------------------------------------------
#
# -----------------------------------------------------------------------
def get_unenriched_commits(
    conn: sqlite3.Connection,
    limit: int | None = None,
) -> list[dict]:
    """
    Henter unike commits som finnes i cve_commit, men ikke i commits.
    """
    sql = """
        SELECT DISTINCT
            cc.repo_url,
            cc.commit_sha,
            cc.commit_url
        FROM cve_commit cc
        LEFT JOIN commits c
            ON c.repo_url = cc.repo_url
           AND c.sha = cc.commit_sha
        WHERE c.sha IS NULL
        ORDER BY random()
    """

    params: tuple = ()
    if limit is not None:
        sql += " LIMIT ?"
        params = (limit,)

    rows = conn.execute(sql, params).fetchall()

    return [
        {
            "repo_url": row[0],
            "commit_sha": row[1],
            "commit_url": row[2],
        }
        for row in rows
    ]

# -----------------------------------------------------------------------
#
# -----------------------------------------------------------------------
def get_sync_state(conn: sqlite3.Connection, source_name: str) -> dict | None:

    row = conn.execute(
        """
        SELECT source_name, release_tag, synced_at
        FROM sync_state
        WHERE source_name = ?
        """,
        (source_name,),
    ).fetchone()

    if not row:
        return None

    return {
        "source_name": row[0],
        "release_tag": row[1],
        "synced_at": row[2],
    }


# -----------------------------------------------------------------------
#
# -----------------------------------------------------------------------
def upsert_sync_state(
    conn: sqlite3.Connection,
    source_name: str,
    release_tag: str,
    synced_at: str,
) -> None:

    conn.execute(
        """
        INSERT INTO sync_state (source_name, release_tag, synced_at)
        VALUES (?, ?, ?)
        ON CONFLICT(source_name) DO UPDATE SET
            release_tag = excluded.release_tag,
            synced_at = excluded.synced_at
        """,
        (source_name, release_tag, synced_at),
    )