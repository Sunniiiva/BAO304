# Felles funksjoner (Bryter circular import)
from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from pydriller import Repository

def extract_repo_and_hash(commit_url):
    """Ekstraher repo URL og commit hash fra GitHub commit URL."""
    if not commit_url or 'github.com' not in commit_url:
        return None
    
    # Fjern markdown-lenke-format først: [text](url) → url
    if '(' in commit_url and ')' in commit_url:
        commit_url = commit_url.split('(')[-1].split(')')[0]
    
    # Fjern protokoll, query-params og fragments
    clean_url = commit_url.replace('https://', '').replace('http://', '').split('?')[0].split('#')[0]
    
    # Split på '/'
    parts = [p for p in clean_url.strip('/').split('/') if p]  # Fjern tomme deler
    
    # Format: github.com/[owner]/[repo]/commit/[hash]
    if len(parts) >= 4 and parts[0] == 'github.com' and parts[3] == 'commit':
        owner = parts[1]
        repo = parts[2]
        commit_hash = parts[4]
        
        return {
            'repo_url': f"https://github.com/{owner}/{repo}",
            'commit_hash': commit_hash
        }
    
    # Format: [owner]/[repo]/commit/[hash] (uten github.com)
    if len(parts) >= 3 and parts[2] == 'commit':
        owner = parts[0]
        repo = parts[1]
        commit_hash = parts[3]
        
        return {
            'repo_url': f"https://github.com/{owner}/{repo}",
            'commit_hash': commit_hash
        }
    
    return None

def fetch_commit_data(repo_url, commit_hash):
    """Hent commit data med pydriller - robust versjon."""
    try:
        repo = Repository(repo_url)
        commit = None
        
        for c in repo.traverse_commits():
            if c.hash == commit_hash:
                commit = c
                break
        
        if not commit:
            return {'error': f'Commit {commit_hash} ikke funnet i {repo_url}'}
        
        files_data = []
        for file in commit.modified_files:
            # Fix: riktig diff-tekst og stats fra PyDriller
            try:
                # PyDriller diff-tekst
                diff_text = str(file.diff) if hasattr(file, 'diff') and file.diff else ''
                
                # Stats (sikker tilgang)
                added = getattr(getattr(file, 'diff_stats', None), 'additions', 0) if hasattr(file, 'diff_stats') else 0
                deleted = getattr(getattr(file, 'diff_stats', None), 'deletions', 0) if hasattr(file, 'diff_stats') else 0
                
                files_data.append({
                    'file_path': file.new_path or file.old_path or 'unknown',
                    'change_type': str(file.change_type) if hasattr(file, 'change_type') else 'unknown',
                    'patch_text': diff_text,
                    'lines_added': added,
                    'lines_deleted': deleted
                })
            except Exception as file_err:
                # Fallback hvis fil-parsing feiler
                files_data.append({
                    'file_path': file.new_path or file.old_path or 'unknown',
                    'change_type': 'unknown',
                    'patch_text': '',
                    'lines_added': 0,
                    'lines_deleted': 0,
                    'error': str(file_err)
                })
        
        return {
            'commit_hash': commit.hash,
            'commit_message': commit.msg,
            'author': commit.author.name if commit.author else 'unknown',
            'date': str(commit.committer_date) if commit.committer_date else '',
            'repo_url': repo_url,
            'modified_files': files_data
        }
        
    except Exception as e:
        return {'error': f'Feil ved henting av {repo_url}@{commit_hash}: {str(e)}'}


def _repo_dir_name(repo_url: str) -> str:
    """
    Lager et stabilt mappenavn fra repo_url, f.eks:
    https://github.com/kpdecker/jsdiff  -> kpdecker_jsdiff
    """
    p = urlparse(repo_url)
    parts = [x for x in p.path.strip("/").split("/") if x]
    if len(parts) >= 2:
        return f"{parts[-2]}_{parts[-1]}"
    return parts[-1] if parts else "repo"


def fetch_commit_modified_files(repo_url: str, commit_sha: str) -> list[dict[str, Any]]:
    if not repo_url:
        raise ValueError("repo_url må settes")

    clone_root = Path("temp_repos")
    clone_root.mkdir(parents=True, exist_ok=True)

    # Egen mappe per repo (hindrer kollisjon)
    repo_dir = clone_root / _repo_dir_name(repo_url)
    repo_dir.mkdir(parents=True, exist_ok=True)

    repo = Repository(
        repo_url,
        clone_repo_to=str(repo_dir),  # <- her tvinger vi bort fra Windows Temp
        single=commit_sha,
    )

    out: list[dict[str, Any]] = []
    for c in repo.traverse_commits():
        for mf in c.modified_files:
            file_path = mf.new_path or mf.old_path or ""
            patch_text = getattr(mf, "diff", None) or ""

            before_code = getattr(mf, "source_code_before", None)
            after_code = getattr(mf, "source_code", None)

            if before_code is None:
                before_code = getattr(mf, "content_before", None)
            if after_code is None:
                after_code = getattr(mf, "content", None)

            out.append(
                {
                    "file_path": file_path,
                    "patch_text": patch_text,
                    "before_code": before_code or "",
                    "after_code": after_code or "",
                }
            )

    return out
