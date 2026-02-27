from __future__ import annotations  # Gjør at type hints evalueres som strenger (unngår sirkulære referanser)

import sqlite3
from pathlib import Path
from typing import Optional  # Brukes for å markere at parametere kan være None

# SQL-skjemaet for databasen (tabeller + indekser)
# Viktig endring: commits har nå composite primary key (repo_url, sha)
# og patch/cve_commit refererer til commits via (repo_url, commit_sha)
# Hele databasen opprettes dynamisk ved hjelp av dette skriptet
SCHEMA_SQL = """
PRAGMA foreign_keys = ON;  -- Sørger for at SQLite håndhever foreign key-regler

CREATE TABLE IF NOT EXISTS cve (
  cve_id      TEXT PRIMARY KEY,  -- Unik identifikator for sårbarheten
  description TEXT,              -- Beskrivelse av sårbarheten
  published   TEXT,              -- Publiseringsdato
  severity    TEXT,              -- Alvorlighetsgrad (f.eks. HIGH, MEDIUM)
  cvss_score  REAL,              -- Numerisk CVSS-score
  cve_title   TEXT,              -- Kort tittel på sårbarheten
  cwe         TEXT,              -- Klassifisering av sårbarhetstype
  state       TEXT               -- Status for CVE (f.eks. PUBLISHED)
);

-- "commit" kan være et reservert SQL-ord, derfor bruker vi "commits"
-- Ny PK: (repo_url, sha) slik at samme sha i ulike repoer ikke kolliderer
CREATE TABLE IF NOT EXISTS commits (
  repo_url      TEXT NOT NULL,   -- Hvilket repository commiten tilhører
  sha           TEXT NOT NULL,   -- Commit-hash
  url           TEXT,            -- URL til commit på GitHub
  message       TEXT,            -- Commit-melding
  commit_date   TEXT,            -- Dato commit ble gjort
  author        TEXT,            -- Forfatter av commit
  authored_date TEXT,            -- Når commit ble skrevet
  PRIMARY KEY (repo_url, sha)    -- Sikrer unikhet per repo
);

-- En rad per fil som ble endret i en commit
-- Må ha både repo_url og commit_sha for å kunne referere til commits PK
CREATE TABLE IF NOT EXISTS patch (
  patch_id      INTEGER PRIMARY KEY AUTOINCREMENT,  -- Intern ID
  repo_url      TEXT NOT NULL,                      -- Referanse til repo
  commit_sha    TEXT NOT NULL,                      -- Referanse til commit
  file_path     TEXT NOT NULL,                      -- Hvilken fil som ble endret
  language      TEXT,                               -- Programmeringsspråk
  added_lines   INTEGER,                            -- Antall linjer lagt til
  removed_lines INTEGER,                            -- Antall linjer fjernet
  hunk_count    INTEGER,                            -- Antall endringsblokker
  diff_text     TEXT,                               -- Selve diff-innholdet
  FOREIGN KEY (repo_url, commit_sha)
    REFERENCES commits(repo_url, sha)
    ON DELETE CASCADE  -- Hvis commit slettes, slettes tilhørende patcher
);

-- Koblingstabell: mange CVE-er kan kobles til mange commits
-- Må ha både repo_url og commit_sha for å peke på riktig commit
CREATE TABLE IF NOT EXISTS cve_commit (
  cve_id     TEXT NOT NULL,      -- Hvilken CVE koblingen gjelder
  repo_url   TEXT NOT NULL,      -- Repository
  commit_sha TEXT NOT NULL,      -- Commit som potensielt fikser CVE
  method     TEXT,               -- Hvordan koblingen ble funnet (regex, heuristikk osv.)
  confidence REAL,               -- Hvor sikker vi er på koblingen (0–1)
  PRIMARY KEY (cve_id, repo_url, commit_sha),
  FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE,
  FOREIGN KEY (repo_url, commit_sha)
    REFERENCES commits(repo_url, sha)
    ON DELETE CASCADE
);

-- Indekser for raskere oppslag når databasen blir større
-- Disse forbedrer ytelsen ved søk og koblinger
CREATE INDEX IF NOT EXISTS idx_patch_repo_sha ON patch(repo_url, commit_sha);
CREATE INDEX IF NOT EXISTS idx_cve_commit_repo_sha ON cve_commit(repo_url, commit_sha);
CREATE INDEX IF NOT EXISTS idx_cve_commit_cve_id ON cve_commit(cve_id);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Åpner/laget sqlite-db på ønsket path og skrur på foreign keys."""
    # Sørger for at mappen eksisterer før databasen opprettes
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Oppretter forbindelse til SQLite-databasen
    conn = sqlite3.connect(str(db_path))

    # Gjør at rader kan behandles som dict-lignende objekter
    conn.row_factory = sqlite3.Row

    # Aktiverer foreign key-støtte eksplisitt
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Oppretter tabeller/indekser hvis de ikke finnes fra før."""
    # Kjører hele SQL-skjemaet i én operasjon
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
    # Upsert-logikk: setter inn ny rad eller oppdaterer eksisterende
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
    # Sikrer at repo_url alltid er satt (del av composite primary key)
    if not repo_url:
        raise ValueError("repo_url must be provided for commits (composite primary key).")

    # Upsert basert på composite key (repo_url, sha)
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
    # Validerer at repo_url finnes siden det er del av foreign key
    if not repo_url:
        raise ValueError("repo_url must be provided for patch rows (FK to commits).")

    # Setter inn én rad per filendring i patch-tabellen
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
    return int(cur.lastrowid)  # Returnerer ID til nyopprettet patch


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
    # Sikrer at koblingen alltid refererer til et konkret repository
    if not repo_url:
        raise ValueError("repo_url must be provided for cve_commit links (FK to commits).")

    # Upsert på koblingstabellen
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
    # Returnerer alle commits som er koblet til en gitt CVE,
    # sortert etter høyest confidence først
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
    # Henter alle filer som ble endret i en bestemt commit
    return conn.execute(
        "SELECT * FROM patch WHERE repo_url = ? AND commit_sha = ?",
        (repo_url, commit_sha),
    ).fetchall()