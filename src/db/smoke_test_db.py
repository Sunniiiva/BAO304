# Enkel "smoke test" for databasen:
# - oppretter DB + tabeller
# - legger inn 1 CVE, 1 commit, 1 patch og en kobling mellom dem
# - skriver ut litt data så vi ser at alt funker

from src.db.database import (
    connect, init_db,
    upsert_cve, upsert_commit,
    insert_patch, link_cve_commit,
    get_commits_for_cve, get_patches_for_commit
)

def main():
    # Lager/åpner test-databasefilen
    conn = connect("data/processed/test.db")
    init_db(conn)  # oppretter tabeller hvis de mangler

    # Testdata (CVE + commit)
    upsert_cve(conn, cve_id="CVE-2024-1234", description="Test vuln", severity="HIGH", cvss_score=8.8)
    upsert_commit(conn, sha="abc123", message="Fix CVE-2024-1234", author="dev", repo_url="https://github.com/x/y")

    # Testdata (patch per fil) + kobling CVE <-> commit
    insert_patch(conn, commit_sha="abc123", file_path="src/app.py", language="Python", added_lines=10, removed_lines=2)
    link_cve_commit(conn, cve_id="CVE-2024-1234", commit_sha="abc123", method="regex", confidence=0.9)

    # Printer ut så vi ser at innsetting og spørringer funker
    print("Commits:", [dict(r) for r in get_commits_for_cve(conn, "CVE-2024-1234")])
    print("Patches:", [dict(r) for r in get_patches_for_commit(conn, "abc123")])

    conn.close()

if __name__ == "__main__":
    main()
