#---------------------------------------------------------------------
# Git-tilgang: tilgangssjekk, token-injeksjon, cache og opprydding.
#---------------------------------------------------------------------

from __future__ import annotations

import logging
import os
import shutil
import stat
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

from contextlib import contextmanager
from pathlib import Path


# Cache for repo-tilgjengelighet så vi slipper å kjøre git ls-remote
# for samme repo tusenvis av ganger i samme kjøring.
_REPO_ACCESS_CACHE: dict[str, tuple[bool, str | None]] = {}
_REPO_ACCESS_LOCK = threading.Lock()


def enable_git_longpaths() -> None:
    """
    Setter git core.longpaths=true globalt.
    Uten dette vil git på Windows nekte å sjekke ut filer
    der den fulle stien overstiger MAX_PATH (260 tegn).
    Trygt å kalle flere ganger — git ignorerer kallet hvis verdien allerede er satt.
    """
    try:
        subprocess.run(
            ["git", "config", "--global", "core.longpaths", "true"],
            capture_output=True,
            timeout=10,
        )
        logger.debug("git core.longpaths=true aktivert")
    except Exception as e:
        logger.warning("Kunne ikke sette core.longpaths: %s", e)


@contextmanager
def _non_interactive_git_env():
    """
    Hindrer git fra å åpne login prompt / credential popup.
    Fungerer spesielt viktig på Windows.
    """
    old_env = os.environ.copy()

    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    os.environ["GCM_INTERACTIVE"] = "Never"
    os.environ["GIT_ASKPASS"] = "echo"

    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def _inject_token(repo_url: str) -> str:
    """
    Injiserer GITHUB_TOKEN fra miljøvariabel inn i GitHub-URL hvis tilgjengelig.
    Øker rate limit fra 60 til 5000 forespørsler per time.
    Tokenet settes som miljøvariabel og lagres aldri i kildekoden.

    Eksempel:
      GITHUB_TOKEN=ghp_abc123 python -m src.main ingest
    """
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token and "github.com" in repo_url:
        return repo_url.replace("https://", f"https://{token}@")
    return repo_url


def _repo_is_accessible(repo_url: str, timeout: int = 20) -> tuple[bool, str | None]:
    """
    Sjekker om repoet kan nås uten interaktiv autentisering.
    Returnerer (True, None) hvis tilgjengelig,
    ellers (False, feilmelding).
    """
    cmd = ["git", "ls-remote", _inject_token(repo_url), "HEAD"]

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "Never"
    env["GIT_ASKPASS"] = "echo"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

        if result.returncode == 0:
            return True, None

        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        msg = stderr or stdout or "Ukjent git-feil"

        lowered = msg.lower()

        if any(x in lowered for x in [
            "could not read username",
            "authentication failed",
            "repository not found",
            "fatal: could not",
            "terminal prompts disabled",
            "support for password authentication was removed",
        ]):
            return False, f"Repo utilgjengelig eller privat: {msg}"

        return False, f"Repo ikke tilgjengelig: {msg}"

    except subprocess.TimeoutExpired:
        return False, "Timeout ved tilgangssjekk mot repo"
    except Exception as e:
        return False, f"Feil ved repo-sjekk: {e}"


def get_cached_repo_access(repo_url: str, timeout: int = 20) -> tuple[bool, str | None]:
    """
    Returnerer cached resultat for repo-tilgjengelighet hvis tilgjengelig.
    Trådsikkert: bruker lock slik at flere workers ikke sjekker samme repo samtidig.
    """
    with _REPO_ACCESS_LOCK:
        cached = _REPO_ACCESS_CACHE.get(repo_url)
        if cached is not None:
            return cached

    result = _repo_is_accessible(repo_url, timeout=timeout)

    with _REPO_ACCESS_LOCK:
        _REPO_ACCESS_CACHE[repo_url] = result
    return result


def clear_repo_access_cache() -> None:
    """
    Tømmer cache for repo-tilgjengelighet.
    Praktisk ved testkjøringer eller hvis man vil starte helt rent.
    """
    _REPO_ACCESS_CACHE.clear()


# ---------------------------------------------------------------------
# Opprydding av midlertidige repo-kloner
# ---------------------------------------------------------------------


def _chmod_tree(path: Path) -> None:
    """
    Setter skrive-tillatelse rekursivt på alle filer og mapper i treet.
    Må gjøres før rmtree på Windows, siden git markerer mange filer som read-only.
    """
    for root, dirs, files in os.walk(path):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            except Exception:
                pass
        for f in files:
            try:
                os.chmod(os.path.join(root, f), stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass


def _rmtree_with_retries(path: Path, retries: int = 20, delay: float = 0.2) -> bool:
    """
    Setter skrive-tillatelse på hele treet før sletting, deretter retryer.
    Returnerer True hvis slettet (eller allerede borte), False hvis fortsatt låst.
    """
    for _ in range(retries):
        if not path.exists():
            return True
        try:
            _chmod_tree(path)
            shutil.rmtree(path)
            return True
        except (PermissionError, FileNotFoundError, OSError):
            time.sleep(delay)
    return not path.exists()


def cleanup_all_temp_repos():
    """
    Sletter temp_repos. På Windows kan filer være låst en kort stund (WinError 32),
    så vi retryer. Hvis det fortsatt er låst, kræsjer vi ikke ingest.
    """
    clear_repo_access_cache()

    clone_root = Path("temp_repos")
    if not clone_root.exists():
        return

    try:
        os.chdir(Path(__file__).resolve().parents[2])
    except Exception:
        pass

    ok = _rmtree_with_retries(clone_root, retries=25, delay=0.2)
    if ok:
        print("Alle temp_repos slettet!")
        return

    ts = int(time.time())
    stale = Path(f"temp_repos__stale_{ts}")
    try:
        clone_root.rename(stale)
        print(f"temp_repos var låst – flyttet til {stale} (kan slettes senere).")
    except Exception:
        print("temp_repos var låst og kunne ikke slettes – lar den ligge.")