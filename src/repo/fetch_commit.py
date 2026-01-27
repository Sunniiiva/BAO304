import json
import re
import os
from datetime import datetime
from pydriller import repository

output_dir = 'data/raw/commits'
os.makedirs(output_dir, exist_ok=True)

# Kalle på referanse objekt fra fetch_cve.py filen. 

def classify_references(references):
    """Sorterer referanser etter type: commit, pull, issue, security
    advisory."""
    classified = {
            'commits': [],
            'pulls': [],
            'issues': [],
            'security_advisories': [],
            'other': []
        }
    
    for url in references:
        if '/commit/' in url:
            classified['commits'].append(url)
        elif '/pull/' in url:
            classified['pulls'].append(url)
        elif '/issues/' in url:
            classified['issues'].append(url)
        elif '/security/advisories/' in url:
            classified['security_advisories'].append(url)
        else:
            classified['other'].append(url)

    return classified

# hente ut repo URL, og commit hash

def extraxt_repo_and_hash(commit_url):
    """Ekstraherer repo URL og commit hash fra Github commit URL."""
    match = re.match(r'(https://github\.com/[^/]+/[^/]+)/commit/([a-f0-9]+)', commit_url)
    if match:
        return {
            'repo_url': match.group(1),
            'commit_hash': match.group(2)
            }
        return None

def extract_repo_from_any_url(url):
    """Ekstraherer repo URL fra enhver GitHub URL (pull, issue, etc.)."""
    match = re.match(r'(https://github\.com/[^/]+/[^/]+)', url)
    return match.group(1) if match else None

# bruke pydriller -> til å klone repo, hente commit metadata og diff/patch data (dette er fra URL)

def fetch_commit_data(repo_url, commit_hash):
    """Bruker pydriller til å klone repo og hente commit metadata +
      diff/patcher."""
    try:
            for commit in Repository(repo_url,
                                     single=commit_hash).traverse_commits():
                    modified_files = []
                    for mod in commit.modified_files:
                        modified_files.append({
                            'path' : mod.new_path or mod.old_path,
                            'change_type': mod.change_type.name,
                            'added_lines': mod.added_lines,
                            'deleted_lines': mod.deleted_lines,
                            'patch': mod.diff # Full diff/patch data
                        })

                    return {
                        'repo_url': repo_url,
                        'commit_hash': commit.hash,
                        'commit_message': commit.msg,
                        'commit_date': commit.committer_date.isoformat(),
                        'author': commit.author.name,
                        'modified_files': modified_files
                    }
        except Exception as e:
            return {'error': str(e), 'repo_url': repo_url, 'commit_hash':
            commit_hash}

# output: repo_url, commit_hash, commit_message, commit_date, modified_files, path, patch
