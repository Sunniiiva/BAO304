def fetch_commit_data(repo_url: str, commit_hash: str):
    """
    Henter metadata og filendringer for en gitt commit ved hjelp av PyDriller.
    Returnerer dict med commit-info og en liste over endrede filer.
    """
    try:
        # Bruk samme klone-strategi som fetch_commit_modified_files()
        clone_root = Path("temp_repos")
        clone_root.mkdir(parents=True, exist_ok=True)

        repo_dir = clone_root / _repo_dir_name(repo_url)
        repo_dir.mkdir(parents=True, exist_ok=True)

        repo = Repository(
            repo_url,
            clone_repo_to=str(repo_dir),  # IKKE system-temp
            single=commit_hash,           # kun denne commiten
        )

        commit = None
        for c in repo.traverse_commits():
            if c.hash == commit_hash:
                commit = c
                break

        if not commit:
            return {"error": f"Commit {commit_hash} ikke funnet i {repo_url}"}

        files_data = []
        methods_before = []
        changed_methods = []
        for file in commit.modified_files:
            try:
                diff_text = str(file.diff) if getattr(file, "diff", None) else ""

                if getattr(file, "diff_stats", None):
                    added = getattr(file.diff_stats, "additions", 0)
                    deleted = getattr(file.diff_stats, "deletions", 0)
                else:
                    added = 0
                    deleted = 0

                
                file_path = file.new_path or file.old_path or "unknown"
                
                if hasattr(file, "change_type"):
                    change_type = str()
                else:
                    change_type = "unknown"
                patch_text = diff_text
                lines_added = added
                lines_deleted = deleted
                error = 0
            except Exception as file_err:
                 change_type = unknown
                 patch_text = ""
                 lines_added = 0
                 lines_added = 0
                 error = str(file_err),
        
            
                    
                
            files_data.append(
                    {
                        "file_path": file.new_path or file.old_path or "unknown", 
                        "change_type": change_type,
                        "patch_text": patch_text,
                        "lines_added": lines_added,
                        "lines_deleted": lines_deleted,
                        "error": error

                    }
                    )

            try: 
                for m in (mf)

            except Exception as file_err:


                return {
                    "commit_hash": commit.hash,
                    "commit_message": commit.msg,
                    "author": commit.author.name if commit.author else "unknown",
                    "date": str(commit.committer_date) if commit.committer_date else "",
                    "repo_url": repo_url,
                    "modified_files": files_data,
                    # ny kode
                    "methods before":
                    "changed_methods": 
                }
            
    except Exception as e:
        return {"error": f"Feil ved henting av {repo_url}@{commit_hash}: {str(e)}"}


def _repo_dir_name(repo_url: str) -> str:
    """
    Lager et stabilt og lesbart mappenavn basert på repo_url.

    Eksempel:
      https://github.com/kpdecker/jsdiff -> kpdecker_jsdiff
    """
    p = urlparse(repo_url)
    parts = [x for x in p.path.strip("/").split("/") if x]
    if len(parts) >= 2:
        return f"{parts[-2]}_{parts[-1]}"
    return parts[-1] if parts else "repo"


def fetch_commit_modified_files(repo_url: str, commit_sha: str) -> list[dict[str, Any]]:
    """
    Henter detaljer om alle filer som er endret i én spesifikk commit.

    Repoet klones til en lokal temp_repos/-mappe, i en egen undermappe per repo.

    Returnerer liste av:
      {
        "file_path": ...,
        "patch_text": ...,
        "before_code": ...,
        "after_code": ...
      }
    """
    if not repo_url:
        raise ValueError("repo_url må settes")

    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    repo_dir = clone_root / _repo_dir_name(repo_url)
    repo_dir.mkdir(parents=True, exist_ok=True)

    repo = Repository(
        repo_url,
        clone_repo_to=str(repo_dir),  # Klon til vår mappe (ikke OS-temp)
        single=commit_sha,            # Begrenser til kun denne commiten
    )

    out: list[dict[str, Any]] = []
    for c in repo.traverse_commits():
        for mf in c.modified_files:
            file_path = mf.new_path or mf.old_path or ""
            patch_text = getattr(mf, "diff", None) or ""

            out.append(
                  {
                    "file_path": file_path,
                    "patch_text": patch_text,
                }
            )

    return out