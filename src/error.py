"""
Error handling for the CVE pipeline project.
Simple custom exceptions for the CVE -> commit -> patch processing.
"""


# Base error class
# Every custom exception in this file inherits from PipelineError, which makes it
# possible to catch ALL pipeline-related errors with a single `except PipelineError`
class PipelineError(Exception):
    """Main exception type for the pipeline."""
    def __init__(self, message):
        # Store the message on the instance so it can be inspected later,
        # then forward it to the built-in Exception so str(e) works as expected
        self.message = message
        super().__init__(self.message)


# CVE-related errors
# All errors that occur while reading or parsing CVE data fall under CVEError
class CVEError(PipelineError):
    """Raised when something goes wrong while processing a CVE."""
    pass


class CVEFileNotFoundError(CVEError):
    """The CVE file does not exist on disk."""
    def __init__(self, filepath):
        # Keep the filepath on the exception so the caller can log or retry it
        self.filepath = filepath
        super().__init__(f"CVE file not found: {filepath}")


class CVEParseError(CVEError):
    """The CVE JSON file could not be parsed."""
    def __init__(self, filepath, reason=None):
        self.filepath = filepath
        self.reason = reason
        # Build the error message dynamically — include the underlying reason if we have it
        msg = f"Could not parse {filepath}"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class CVEMissingFieldError(CVEError):
    """A required field is missing from the CVE data."""
    def __init__(self, field_name, cve_id=None):
        # field_name = which field is missing, cve_id = which CVE is broken (optional)
        self.field_name = field_name
        self.cve_id = cve_id
        msg = f"Missing field: {field_name}"
        if cve_id:
            msg += f" in {cve_id}"
        super().__init__(msg)


# Commit / GitHub errors
# Errors that occur while fetching or accessing Git commits
class CommitError(PipelineError):
    """Raised when a commit operation fails."""
    pass


class CommitFetchError(CommitError):
    """Could not fetch the commit from GitHub."""
    def __init__(self, repo_url, commit_hash):
        self.repo_url = repo_url
        self.commit_hash = commit_hash
        # Show only the first 8 chars of the SHA — enough to identify it without cluttering logs
        super().__init__(f"Could not fetch commit {commit_hash[:8]} from {repo_url}")


class CommitNotFoundError(CommitError):
    """The commit does not exist in the repository."""
    def __init__(self, commit_hash, repo_url):
        # Different from CommitFetchError: the network call worked, but the SHA does not exist.
        # This usually means the commit was deleted or rewritten via a force-push
        self.commit_hash = commit_hash
        self.repo_url = repo_url
        super().__init__(f"Commit {commit_hash} not found in {repo_url}")


class RepositoryAccessError(CommitError):
    """No access to the repository."""
    def __init__(self, repo_url, reason=None):
        # Raised when the repo is private, deleted, or the user lacks credentials
        self.repo_url = repo_url
        self.reason = reason
        msg = f"No access to repository: {repo_url}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


# Patch / diff errors
# Errors related to building or interpreting the actual code diff
class PatchError(PipelineError):
    """Raised when a patch operation fails."""
    pass


class PatchFetchError(PatchError):
    """Could not fetch patch data."""
    def __init__(self, commit_hash, file_path=None):
        # file_path is optional — sometimes the patch fetch fails for the whole commit,
        # other times it fails only for a single file
        self.commit_hash = commit_hash
        self.file_path = file_path
        msg = f"Could not fetch patch for commit {commit_hash[:8]}"
        if file_path:
            msg += f" (file: {file_path})"
        super().__init__(msg)


class PatchParseError(PatchError):
    """Could not parse a patch / diff."""
    def __init__(self, file_path):
        # Raised when a diff exists but is malformed or unparseable
        self.file_path = file_path
        super().__init__(f"Could not parse patch for {file_path}")


# Database errors
# Errors related to SQLite operations
class DatabaseError(PipelineError):
    """Raised when a database operation fails."""
    pass


class DatabaseConnectionError(DatabaseError):
    """Cannot connect to the database."""
    def __init__(self, db_path):
        # The DB file is missing, locked, or corrupt
        self.db_path = db_path
        super().__init__(f"Could not connect to database: {db_path}")


class DatabaseInsertError(DatabaseError):
    """Could not insert data into the database."""
    def __init__(self, table, details=None):
        # Typically raised on a constraint violation (UNIQUE, FOREIGN KEY, NOT NULL, etc.)
        self.table = table
        self.details = details
        msg = f"Insert failed in {table}"
        if details:
            msg += f": {details}"
        super().__init__(msg)


class DatabaseQueryError(DatabaseError):
    """A database query failed."""
    def __init__(self, query_type):
        # Raised when a SELECT/UPDATE/DELETE fails — for example because of a syntax error
        # or a locked database
        self.query_type = query_type
        super().__init__(f"Database query failed: {query_type}")


# Network errors
# Errors that occur during network requests
class NetworkError(PipelineError):
    """Raised when a network operation fails."""
    pass


class GitHubAPIError(NetworkError):
    """A GitHub API request failed."""
    def __init__(self, endpoint, status_code=None):
        # status_code lets the caller decide what to do (e.g. retry on 5xx, give up on 4xx)
        self.endpoint = endpoint
        self.status_code = status_code
        msg = f"GitHub API error: {endpoint}"
        if status_code:
            msg += f" (status {status_code})"
        super().__init__(msg)


class RateLimitError(NetworkError):
    """Hit GitHub's API call limit (rate limit)."""
    def __init__(self):
        # GitHub limits anonymous traffic to 60 requests/hour and authenticated traffic
        # to 5000 requests/hour — when we hit the cap, we have to wait
        super().__init__("GitHub rate limit exceeded - try again later")


class TimeoutError(NetworkError):
    """The request timed out."""
    def __init__(self, url, timeout_seconds=30):
        # NOTE: This shadows Python's built-in TimeoutError inside this module.
        # That is intentional here so the rest of the codebase can use the project's
        # own version, but be aware of it when importing in other files
        self.url = url
        self.timeout_seconds = timeout_seconds
        super().__init__(f"Request timed out after {timeout_seconds}s: {url}")


# Helper functions
def safe_get(data, *keys, default=None):
    """
    Get nested values from a dict without risking a KeyError.

    Usage:
        cve_id = safe_get(data, 'cveMetadata', 'cveId', default='unknown')
    """
    # *keys lets the caller pass any number of nested keys.
    # Useful because CVE JSON has deeply nested structures and we don't want
    # to write `data.get(...).get(...).get(...)` chains everywhere
    try:
        result = data
        # Walk the dict one key at a time
        for key in keys:
            result = result[key]
        return result
    except (KeyError, TypeError):
        # KeyError = the key is missing
        # TypeError = an intermediate value is None or not subscriptable
        # In both cases, return the default instead of crashing
        return default


def handle_file_error(operation, filepath):
    """
    Wrapper for file operations that translates errors to project-specific exceptions.

    Usage:
        data = handle_file_error(lambda: json.load(f), 'cve.json')
    """
    # `operation` is a callable (typically a lambda) so we can wrap any file action
    # with consistent error translation
    try:
        return operation()
    except FileNotFoundError:
        # Translate Python's built-in error to our project-specific exception
        raise CVEFileNotFoundError(filepath)
    except Exception as e:
        # Any other failure (JSON decode, encoding error, etc.) is treated as a parse error
        raise CVEParseError(filepath, reason=str(e))


def handle_db_error(operation, context="database operation"):
    """
    Wrapper for database operations that translates SQLite errors into project exceptions.

    Usage:
        handle_db_error(lambda: conn.execute(sql), "insert CVE")
    """
    # Imported here (instead of at the top) so the module does not depend on sqlite3
    # unless this function is actually used
    import sqlite3
    try:
        return operation()
    except sqlite3.IntegrityError as e:
        # IntegrityError = constraint violation (e.g. duplicate primary key, NULL in NOT NULL column)
        raise DatabaseInsertError(context, str(e))
    except sqlite3.OperationalError as e:
        # OperationalError = problem with the operation itself (locked DB, syntax error, etc.)
        raise DatabaseQueryError(context)
    except Exception as e:
        # Catch-all so unexpected errors are still wrapped in our hierarchy
        raise DatabaseError(f"{context}: {str(e)}")


# Example usage
# Runs only when this file is executed directly, not on import.
# Acts as a small smoke test that the exception classes work as expected
if __name__ == "__main__":
    # Test the error message
    # Verify that a custom exception can be raised and caught correctly
    try:
        raise CVEFileNotFoundError("test.json")
    except CVEFileNotFoundError as e:
        print(f"Caught error: {e}")

    # Test safe_get
    # Verify that safe_get reaches a deeply nested value without crashing
    data = {'cveMetadata': {'cveId': 'CVE-2024-1234'}}
    cve_id = safe_get(data, 'cveMetadata', 'cveId', default='unknown')
    print(f"CVE ID: {cve_id}")

    print("\nError classes loaded successfully!")