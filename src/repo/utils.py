# Felles funksjoner (Bryter circular import)
import re
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
        from pydriller import Repository
        
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


if __name__ == "__main__":
    test_url = "https://github.com/kpdecker/jsdiff/commit/15a1585230748c8ae6f8274c202e0c87309142f5"
    result = extract_repo_and_hash(test_url)
    print(f"Test URL: {test_url}")
    print(f"Result: {result}")
