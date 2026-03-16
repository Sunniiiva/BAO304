
#--------------------------------------------------------------
# IMPORTS: impoterer biblitekene som trengs for DB-hånteringen
#---------------------------------------------------------------
from __future__ import annotations 
import sqlite3
from pathlib import Path
from typing import Optional  

#----------------------------
# DATABASE SKJEMA
#----------------------------

# Denne sql-strengen definerer hele database-strukturen
# CVE: lagrer informasjon om sårbarheter
# commits: lagrer informasjon om commiter
# patch: lagrer filendringer for commits
# functions: lagrer sårbar og patched funskjonskode
# cve_commit: koblingstabell mellom CVE-er og commits
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
  before_code   TEXT,
  after_code    TEXT,
  FOREIGN KEY (repo_url, commit_sha)
    REFERENCES commits(repo_url, sha)
    ON DELETE CASCADE  -- Hvis commit slettes, slettes tilhørende patcher
);

CREATE TABLE IF NOT EXISTS functions (
  function_id     INTEGER PRIMARY KEY AUTOINCREMENT,  -- Unik ID for function-raden
  repo_url        TEXT NOT NULL,                      -- Hvilket repository funksjonen tilhører
  commit_sha      TEXT NOT NULL,                      -- Commit-hash funksjonen er knyttet til
  file_path       TEXT,                               -- Hvilken fil funksjonen ligger i
  method_name     TEXT,                               -- Navnet på metoden funksjonen hører til
  start_line      INTEGER,                            
  end_line        INTEGER,
  vuln_function   TEXT,                               -- Funksjonen som inneholder sårbarheten
  patch_function  TEXT,                               -- Funksjonen der patchen er gjort
  FOREIGN KEY (repo_url, commit_sha)
    REFERENCES commits(repo_url, sha)
    ON DELETE CASCADE  -- Hvis commit slettes, slettes tilhørende function-rader
);

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
CREATE INDEX IF NOT EXISTS idx_patch_repo_sha ON patch(repo_url, commit_sha);
CREATE INDEX IF NOT EXISTS idx_functions_repo_sha ON functions(repo_url, commit_sha);
CREATE INDEX IF NOT EXISTS idx_cve_commit_repo_sha ON cve_commit(repo_url, commit_sha);
CREATE INDEX IF NOT EXISTS idx_cve_commit_cve_id ON cve_commit(cve_id);
"""

#-------------------------------------------------------
# FUNKSJON: connect, oppretter tilkobling til SQLite-DB
#--------------------------------------------------------
def connect(db_path: str | Path) -> sqlite3.Connection:
    
# Åpner/laget sqlite-db på ønsket path og skrur på foreign keys.
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

# Oppretter forbindelse til SQLite-databasen
    conn = sqlite3.connect(str(db_path))
    
# gjør at vi kan lese rader som dict-lignende
    conn.row_factory = sqlite3.Row 
     
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

#-----------------------------------------------..................................
# Funksjon: initialiserer databsen ved å kjøre hele databaseskjemaet i SCHEMA_SQL
#---------------------------------------------------------------------------------
def init_db(conn: sqlite3.Connection) -> None:
    
# Oppretter tabeller/indekser hvis de ikke finnes fra før.
    conn.executescript(SCHEMA_SQL)
    conn.commit()

#-----------------------------------------------------------------------------------
# Funksjon: legger inn en CVE i DB, eller oppdaterer den hvis den allerede finnes
#------------------------------------------------------------------------------------
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
    
# Legger inn CVE, eller oppdaterer hvis den finnes fra før
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

#------------------------------------------------------------------------------------
# Funksjon: Legger inn en commit i DB, eller oppdaterer den hvis den allerede finnes
#-------------------------------------------------------------------------------------
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
    
# Legger inn commit, eller oppdaterer hvis den finnes fra før (unikt per repo_url+sha).
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

#-----------------------------------------
# Funksjon: legger inn en patch-rad i db
#-----------------------------------------
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
    diff_text: Optional[str] = None,
    before_code: Optional[str] = None,
    after_code: Optional[str] = None,
    changed_lines: Optional[int] = None,
) -> int:
    
# Legger inn en patch-rad (typisk per fil i en commit).
    if not repo_url:
        raise ValueError("repo_url must be provided for patch rows (FK to commits).")

    cur = conn.execute(
        """
        INSERT INTO patch(
          repo_url, commit_sha, file_path, language,
          added_lines, removed_lines, hunk_count,
          diff_text, before_code, after_code
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    conn.commit()
    return int(cur.lastrowid)

# ---------------------------------------------
# Funksjon: Legger inn en funskjonsrad i DB
# ---------------------------------------------
def insert_function(
    conn: sqlite3.Connection,
    *,
    repo_url: str,
    commit_sha: str,
    file_path: Optional[str] = None,
    method_name: Optional[str] = None,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
    vuln_function: Optional[str] = None,
    patch_function: Optional[str] = None,
) -> int:
   
#Legger inn en function-rad knyttet til en commit.
    if not repo_url:
        raise ValueError("repo_url must be provided for function rows (FK to commits).")

    cur = conn.execute(
        """
        INSERT INTO functions(
          repo_url, commit_sha, file_path, method_name, start_line, end_line,
          vuln_function, patch_function
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            repo_url,
            commit_sha,
            file_path,
            method_name,
            start_line,
            end_line,
            vuln_function,
            patch_function,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)

#-------------------------------------------------------
# Funksjon: oppretter en kobling mellom CVE og en commit
#-------------------------------------------------------

def link_cve_commit(
    conn: sqlite3.Connection,
    *,
    cve_id: str,
    repo_url: str,
    commit_sha: str,
    method: Optional[str] = None,
    confidence: Optional[float] = None,
) -> None:
    
# Lager/oppdaterer kobling mellom en CVE og en commit.
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


#----------------------------------------------------------------
# Funskjon: henter alle commits som er koblet til en bestemt CVE
#----------------------------------------------------------------
def get_commits_for_cve(conn: sqlite3.Connection, cve_id: str):

# Henter commits koblet til en CVE (nyttig for debugging/analyse).
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


# ------------------------------------------------------------------------
# Funksjon: henter alle patch rader som er lagret for en bestemt commit
#--------------------------------------------------------------------------
def get_patches_for_commit(conn: sqlite3.Connection, repo_url: str, commit_sha: str):

# Henter patch-rader (filendringer) for en commit.
    return conn.execute(
        "SELECT * FROM patch WHERE repo_url = ? AND commit_sha = ?",
        (repo_url, commit_sha),
    ).fetchall()

# -------------------------------------------------------------------------
# Funksjon: som henter alle funskjoner som er lagret for en bestemt commit
# --------------------------------------------------------------------------
def get_functions_for_commit(conn: sqlite3.Connection, repo_url: str, commit_sha: str):
    
# Henter function-rader for en commit.
    return conn.execute(
        """
        SELECT 
        file_path,
        method_name,
        start_line,
        end_line,
        vuln_function,
        patch_function
        FROM functions
        WHERE repo_url = ? AND commit_sha = ?
        ORDER BY file_path, method_name 
        """,
        (repo_url, commit_sha),
    ).fetchall()
    

#----------------------------------------------------------------------------------------
# Funksjon: som henter en enkel oversikt over lagrende funksjoner sammen med commit-info
#------------------------------------------------------------------------------------------
def get_function_overview(conn: sqlite3.Connection):
    
# Henter oversikt med commit-melding, SHA, vuln_function og patch_function.
    return conn.execute(
        """
        SELECT
          c.message AS commit,
          f.commit_sha AS sha,
          f.vuln_function,
          f.patch_function
        FROM functions f
        JOIN commits c
          ON c.repo_url = f.repo_url
         AND c.sha = f.commit_sha
        """
    ).fetchall()