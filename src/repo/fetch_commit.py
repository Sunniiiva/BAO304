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


# bruke pydriller -> til å klone repo, hente commit metadata og diff/patch data (dette er fra URL)
# output: repo_url, commit_hash, commit_message, commit_date, modified_files, path, patch
