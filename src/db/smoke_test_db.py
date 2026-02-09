# Enkel "smoke test" for databasen:
# - oppretter DB + tabeller
# - legger inn 1 CVE, 1 commit, 1 patch og en kobling mellom dem
# - skriver ut litt data så vi ser at alt funker

from src.db.database import (
    connect,
    init_db,
    upsert_cve,
    upsert_commit,
    insert_patch,
    link_cve_commit,
    get_commits_for_cve,
    get_patches_for_commit,
)


def main():
    # Lager/åpner test-databasefilen
    conn = connect("data/processed/test.db")
    init_db(conn)  # oppretter tabeller hvis de mangler

    # Testdata
    repo_url = "https://github.com/x/y"
    sha = "abc123"
    cve_id = "CVE-2024-1234"

    # CVE + commit
    upsert_cve(
        conn,
        cve_id=cve_id,
        description="Test vuln",
        severity="HIGH",
        cvss_score=8.8,
    )

    # NB: upsert_commit krever repo_url nå
    upsert_commit(
        conn,
        repo_url=repo_url,
        sha=sha,
        message="Fix CVE-2024-1234",
        author="dev",
    )

    # Patch per fil (NB: insert_patch krever repo_url nå)
    insert_patch(
        conn,
        repo_url=repo_url,
        commit_sha=sha,
        file_path="src/app.py",
        language="Python",
        added_lines=10,
        removed_lines=2,
        diff_text="@@ -1 +1 @@\n- vuln()\n+ fix()\n",
    )

    # Link CVE <-> commit (NB: link_cve_commit krever repo_url nå)
    link_cve_commit(
        conn,
        cve_id=cve_id,
        repo_url=repo_url,
        commit_sha=sha,
        method="regex",
        confidence=0.9,
    )

    # Printer ut så vi ser at innsetting og spørringer funker
    print("Commits:", [dict(r) for r in get_commits_for_cve(conn, cve_id)])

    # NB: get_patches_for_commit krever repo_url + commit_sha nå
    print("Patches:", [dict(r) for r in get_patches_for_commit(conn, repo_url, sha)])


if __name__ == "__main__":
    main()