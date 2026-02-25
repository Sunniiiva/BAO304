"""
Feilhåndtering for CVE-pipeline-prosjektet
Enkle tilpassede unntak for prosessering av CVE -> commit -> patch
"""


# Basisklasse for feil
class PipelineError(Exception):
    """Hovedfeil for pipelinen"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


# CVE-relaterte feil
class CVEError(PipelineError):
    """Noe gikk galt under prosessering av CVE"""
    pass


class CVEFileNotFoundError(CVEError):
    """CVE-filen eksisterer ikke"""
    def __init__(self, filepath):
        self.filepath = filepath
        super().__init__(f"Fant ikke CVE-fil: {filepath}")


class CVEParseError(CVEError):
    """Kan ikke tolke (parse) CVE JSON-filen"""
    def __init__(self, filepath, reason=None):
        self.filepath = filepath
        self.reason = reason
        msg = f"Kunne ikke tolke {filepath}"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class CVEMissingFieldError(CVEError):
    """Påkrevd felt mangler i CVE-data"""
    def __init__(self, field_name, cve_id=None):
        self.field_name = field_name
        self.cve_id = cve_id
        msg = f"Mangler felt: {field_name}"
        if cve_id:
            msg += f" i {cve_id}"
        super().__init__(msg)


# Commit/GitHub-feil
class CommitError(PipelineError):
    """Noe gikk galt under commit-operasjoner"""
    pass


class CommitFetchError(CommitError):
    """Kunne ikke hente commit fra GitHub"""
    def __init__(self, repo_url, commit_hash):
        self.repo_url = repo_url
        self.commit_hash = commit_hash
        super().__init__(f"Kunne ikke hente commit {commit_hash[:8]} fra {repo_url}")


class CommitNotFoundError(CommitError):
    """Commit eksisterer ikke i repositoriet"""
    def __init__(self, commit_hash, repo_url):
        self.commit_hash = commit_hash
        self.repo_url = repo_url
        super().__init__(f"Fant ikke commit {commit_hash} i {repo_url}")


class RepositoryAccessError(CommitError):
    """Ingen tilgang til repositoriet"""
    def __init__(self, repo_url, reason=None):
        self.repo_url = repo_url
        self.reason = reason
        msg = f"Har ikke tilgang til repositorium: {repo_url}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


# Patch/diff-feil
class PatchError(PipelineError):
    """Noe gikk galt under patch-operasjoner"""
    pass


class PatchFetchError(PatchError):
    """Kunne ikke hente patch-data"""
    def __init__(self, commit_hash, file_path=None):
        self.commit_hash = commit_hash
        self.file_path = file_path
        msg = f"Kunne ikke hente patch for commit {commit_hash[:8]}"
        if file_path:
            msg += f" (fil: {file_path})"
        super().__init__(msg)


class PatchParseError(PatchError):
    """Kunne ikke tolke patch/diff"""
    def __init__(self, file_path):
        self.file_path = file_path
        super().__init__(f"Kunne ikke tolke patch for {file_path}")


# Database-feil
class DatabaseError(PipelineError):
    """Noe gikk galt under database-operasjoner"""
    pass


class DatabaseConnectionError(DatabaseError):
    """Kan ikke koble til databasen"""
    def __init__(self, db_path):
        self.db_path = db_path
        super().__init__(f"Kunne ikke koble til database: {db_path}")


class DatabaseInsertError(DatabaseError):
    """Kunne ikke sette inn data"""
    def __init__(self, table, details=None):
        self.table = table
        self.details = details
        msg = f"Feil ved innsetting i {table}"
        if details:
            msg += f": {details}"
        super().__init__(msg)


class DatabaseQueryError(DatabaseError):
    """Spørring feilet"""
    def __init__(self, query_type):
        self.query_type = query_type
        super().__init__(f"Databasespørring feilet: {query_type}")


# Nettverksfeil
class NetworkError(PipelineError):
    """Nettverksoperasjon feilet"""
    pass


class GitHubAPIError(NetworkError):
    """GitHub API-forespørsel feilet"""
    def __init__(self, endpoint, status_code=None):
        self.endpoint = endpoint
        self.status_code = status_code
        msg = f"GitHub API-feil: {endpoint}"
        if status_code:
            msg += f" (status {status_code})"
        super().__init__(msg)


class RateLimitError(NetworkError):
    """Nådde GitHubs grense for antall kall (rate limit)"""
    def __init__(self):
        super().__init__("GitHub rate limit overskredet - prøv igjen senere")


class TimeoutError(NetworkError):
    """Forespørselen ble tidsavbrutt"""
    def __init__(self, url, timeout_seconds=30):
        self.url = url
        self.timeout_seconds = timeout_seconds
        super().__init__(f"Forespørsel tidsavbrutt etter {timeout_seconds}s: {url}")


# Hjelpefunksjoner
def safe_get(data, *keys, default=None):
    """
    Henter nestede verdier fra en dict uten risiko for KeyError

    Bruk:
        cve_id = safe_get(data, 'cveMetadata', 'cveId', default='ukjent')
    """
    try:
        result = data
        for key in keys:
            result = result[key]
        return result
    except (KeyError, TypeError):
        return default


def handle_file_error(operation, filepath):
    """
    Wrapper for filoperasjoner for å håndtere feil

    Bruk:
        data = handle_file_error(lambda: json.load(f), 'cve.json')
    """
    try:
        return operation()
    except FileNotFoundError:
        raise CVEFileNotFoundError(filepath)
    except Exception as e:
        raise CVEParseError(filepath, reason=str(e))


def handle_db_error(operation, context="databaseoperasjon"):
    """
    Wrapper for databaseoperasjoner

    Bruk:
        handle_db_error(lambda: conn.execute(sql), "sett inn CVE")
    """
    import sqlite3
    try:
        return operation()
    except sqlite3.IntegrityError as e:
        raise DatabaseInsertError(context, str(e))
    except sqlite3.OperationalError as e:
        raise DatabaseQueryError(context)
    except Exception as e:
        raise DatabaseError(f"{context}: {str(e)}")


# Eksempel på bruk
if __name__ == "__main__":
    # Test av feilmeldinger
    try:
        raise CVEFileNotFoundError("test.json")
    except CVEFileNotFoundError as e:
        print(f"Fanget feil: {e}")

    # Test av safe_get
    data = {'cveMetadata': {'cveId': 'CVE-2024-1234'}}
    cve_id = safe_get(data, 'cveMetadata', 'cveId', default='ukjent')
    print(f"CVE ID: {cve_id}")

    print("\nFeil-klasser lastet opp suksessfullt!")