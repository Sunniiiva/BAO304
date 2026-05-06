"""
Test for multi-plattform URL-parsing i src/repo/utils.py.
Kjør fra prosjektrot (BAO304/):
    python src/test_multi_platform.py
"""
from __future__ import annotations

import os
import sys


if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.repo.utils import (
    extract_repo_and_hash,
    detect_platform,
    _inject_token,
)


test_cases = [
    ("https://github.com/torvalds/linux/commit/abc123def4567890",
     "https://github.com/torvalds/linux", "abc123def4567890", "github"),
    ("https://github.com/owner/repo/commit/1234567",
     "https://github.com/owner/repo", "1234567", "github"),
    ("[link](https://github.com/owner/repo/commit/abcdef1234567890)",
     "https://github.com/owner/repo", "abcdef1234567890", "github"),
    ("https://github.com/owner/repo/commit/abcdef1?diff=split",
     "https://github.com/owner/repo", "abcdef1", "github"),
    ("https://gitlab.com/group/project/-/commit/deadbeefcafe",
     "https://gitlab.com/group/project", "deadbeefcafe", "gitlab"),
    ("https://gitlab.com/group/project/commit/deadbeefcafe",
     "https://gitlab.com/group/project", "deadbeefcafe", "gitlab"),
    ("https://bitbucket.org/team/repo/commits/abc1234",
     "https://bitbucket.org/team/repo", "abc1234", "bitbucket"),
    ("https://bitbucket.org/team/repo/commit/abc1234",
     "https://bitbucket.org/team/repo", "abc1234", "bitbucket"),
    ("https://github.com/owner/repo.git/commit/abc1234",
     "https://github.com/owner/repo", "abc1234", "github"),
]

negative_cases = [
    "https://example.com/owner/repo/commit/abc123",
    "https://github.com/owner/repo",
    "https://sourceforge.net/p/project/ci/abc",
    "",
    None,
]


def main() -> int:
    # Counts how many tests failed across all sections — returned as exit code at the end
    fails = 0

    # ---- Section 1: positive cases ----
    print("=" * 70)
    print("Positive tester (URL-er som SKAL parses):")
    print("=" * 70)
    for url, expected_repo, expected_hash, expected_platform in test_cases:
        result = extract_repo_and_hash(url)
        # All three fields must match for the test to pass
        ok = (result is not None
              and result["repo_url"] == expected_repo
              and result["commit_hash"] == expected_hash
              and result["platform"] == expected_platform)
        status = "OK " if ok else "XX "
        print(f"{status} {url}")
        if not ok:
            fails += 1
            # Print expected vs actual to make debugging easier
            print(f"    Forventet: repo={expected_repo}, hash={expected_hash}, platform={expected_platform}")
            print(f"    Fikk:      {result}")

    # ---- Section 2: negative cases ----
    print()
    print("=" * 70)
    print("Negative tester (URL-er som IKKE skal parses):")
    print("=" * 70)
    for url in negative_cases:
        result = extract_repo_and_hash(url)
        # For a negative case, returning None means it correctly rejected the input
        ok = result is None
        status = "OK " if ok else "XX "
        print(f"{status} {url!r} -> {result}")
        if not ok:
            fails += 1

    # ---- Section 3: platform detection on its own ----
    print()
    print("=" * 70)
    print("Plattform-deteksjon:")
    print("=" * 70)
    # Tests detect_platform separately from URL parsing.
    # SourceForge is not supported — should return None
    platform_tests = [
        ("https://github.com/a/b", "github"),
        ("https://gitlab.com/a/b", "gitlab"),
        ("https://bitbucket.org/a/b", "bitbucket"),
        ("https://sourceforge.net/a/b", None),
    ]
    for url, expected in platform_tests:
        got = detect_platform(url)
        ok = got == expected
        status = "OK " if ok else "XX "
        print(f"{status} {url} -> {got} (forventet {expected})")
        if not ok:
            fails += 1

    # ---- Section 4: token injection (mocked environment variables) ----
    print()
    print("=" * 70)
    print("Token-injeksjon (med mock env):")
    print("=" * 70)
    # Save the user's real tokens (if any) so we can restore them afterward.
    # This prevents the test from clobbering credentials in the developer's shell.
    old_env = {
        k: os.environ.get(k)
        for k in ("GITHUB_TOKEN", "GITLAB_TOKEN", "BITBUCKET_TOKEN")
    }
    # Set fake tokens just for the duration of these tests
    os.environ["GITHUB_TOKEN"] = "ghp_test123"
    os.environ["GITLAB_TOKEN"] = "glpat_test456"
    os.environ["BITBUCKET_TOKEN"] = "bbt_test789"

    try:
        # Each Git host expects the token in a different URL format:
        #   GitHub:    https://TOKEN@host/...
        #   GitLab:    https://oauth2:TOKEN@host/...
        #   Bitbucket: https://x-token-auth:TOKEN@host/...
        token_tests = [
            ("https://github.com/a/b",    "https://ghp_test123@github.com/a/b"),
            ("https://gitlab.com/a/b",    "https://oauth2:glpat_test456@gitlab.com/a/b"),
            ("https://bitbucket.org/a/b", "https://x-token-auth:bbt_test789@bitbucket.org/a/b"),
        ]
        for url, expected in token_tests:
            got = _inject_token(url)
            ok = got == expected
            status = "OK " if ok else "XX "
            print(f"{status} {url}")
            print(f"   -> {got}")
            if not ok:
                fails += 1
                print(f"   Forventet: {expected}")
    finally:
        # Always restore the original environment, even if a test crashed.
        # If the variable did not exist before, remove it instead of setting it to None.
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # ---- Final summary ----
    print()
    print("=" * 70)
    if fails == 0:
        print("ALLE TESTER BESTATT")
    else:
        print(f"{fails} tester feilet")
    print("=" * 70)
    # Return failure count so the caller (or CI) can detect failures via the exit code
    return fails


if __name__ == "__main__":
    # sys.exit with the failure count: 0 means success, anything else means failure
    sys.exit(main())