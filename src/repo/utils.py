# Felles funksjoner (Bryter circular import)
import re
from pydriller import Repository

def extract_repo_and_hash(commit_url):
    """Ekstraher repo URL og commit hash fra GitHub URL"""
    if not commit_url or 'github.com' not in commit_url:
        return None
    
    parts = commit_url.strip('/').split('/')
    if len(parts) >= 4:
        repo_path = '/'.join(parts[-2:])
        commit_hash = parts[-1]
        return {
            'repo_url': f"https://github.com/{repo_path}",
            'commit_hash': commit_hash
        }
    return None

def fetch_commit_data(repo_url, commit_hash):
    """Hent commit data med pydriller"""
    try:
        repo = Repository(repo_url)
        commit = None
        
        for c in repo.traverse_commits():
            if c.hash == commit_hash:
                commit = c
                break
        
        if not commit:
            return {'error': f'Commit {commit_hash} ikke funnet'}
        
        files_data = []
        for file in commit.modified_files:
            files_data.append({
                'filename': file.new_path or file.old_path or 'unknown',
                'change_type': file.change_type.name if hasattr(file.change_type, 'name') else str(file.change_type),
                'patch_text': file.diff.parse_patch() if file.diff else '',
                'lines_added': file.diff_stats.additions if hasattr(file, 'diff_stats') else 0,
                'lines_deleted': file.diff_stats.deletions if hasattr(file, 'diff_stats') else 0
            })
        
        return {
            'commit_hash': commit.hash,
            'commit_message': commit.msg,
            'author': commit.author.name,
            'date': str(commit.committer_date),
            'modified_files': files_data
        }
    except Exception as e:
        return {'error': f'Feil ved henting: {str(e)}'}
    
def fetch_commit_modified_files(repo_url, commit_hash):
    """
    Hjelpefunksjon for fetch_patch.py (Sunniva):
    Hent kun modified_files fra commit - uten full commit data.
    """
    commit_data = fetch_commit_data(repo_url, commit_hash)
    
    # Returner tom liste ved error
    if 'error' in commit_data:
        return []
    
    return commit_data.get('modified_files', [])
