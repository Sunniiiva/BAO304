# Klassifisering av sårbar vs patchet kode på LINJENIVÅ, per CWE.
# Speiler ml_line_level.py i alle metodiske valg (samme features, tokenizer,
# CV, leakage-håndtering), men trener én sett modeller per CWE med >= 25 par.
#
# Label: 0 = sårbar (linje fjernet i patch), 1 = patchet (linje lagt til i patch)
#
# Kjør: python src/machine_learning/ml_line_level_cwe.py

from __future__ import annotations

import os
# Må settes FØR sklearn-import slik at joblib worker-prosesser arver det
os.environ["PYTHONWARNINGS"] = "ignore"

import difflib
import re
import sqlite3
import time
import warnings
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy.sparse as sp

from sklearn.base import clone
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import (
    AdaBoostClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, RidgeClassifier, SGDClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.naive_bayes import ComplementNB, MultinomialNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)


# KONFIGURASJON
DB_PATH = Path("data/processed/cve_commits.db")
OUTPUT_DIR = Path("src/machine_learning/output/per_cwe")

CONTEXT_WINDOW = 3
MIN_PAIRS_PER_CWE = 25
MAX_ROWS_PER_CODE_LABEL = 5
N_FOLDS = 5
RANDOM_STATE = 42


# --------------------------------------------------------------
# 1. NOISE FILTERING + TOKENIZER (felles med global-filen)
_TRIVIAL = {"{", "}", "(", ")", "[", "]", ";", ",", "else", "try",
            "finally", "pass", "break", "continue", "default", "case"}
_COMMENT = ("#", "//", "/*", "*", "*/", "--")
_IMPORT = re.compile(r"^(from|import|using|package|namespace)\b")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|==|!=|<=|>=|&&|\|\||[-+*/%<>]=")


def normalize_line(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def code_tokenizer(s: str) -> list[str]:
    """Custom tokenizer for kildekode — beholder identifiers og operatorer som tokens."""
    return _TOKEN.findall(s or "")


def is_noise(line: str) -> bool:
    if not line:
        return True
    if line in _TRIVIAL or line.startswith(_COMMENT) or _IMPORT.match(line):
        return True
    if len(line) < 4 or len(line) > 300:
        return True
    if re.fullmatch(r"[\W_]+", line):
        return True
    return len(code_tokenizer(line)) < 2


# --------------------------------------------------------------
# 2. BINARY EKSPERT-FEATURES (felles med global-filen)
_PATTERNS = {
    "has_user_input": re.compile(
        r"\$_(?:POST|GET|REQUEST|COOKIE|FILES|SERVER)\b"
        r"|req(?:uest)?\.(?:body|query|params|cookies|headers)"
        r"|request\.(?:GET|POST|args|form|json|data|cookies|headers)"
        r"|\binput\s*\(|getParameter\s*\(|@RequestParam|\bargv\["
        r"|\bgets\s*\(|fgets\s*\(|scanf\s*\("
    ),
    "has_sanitizer": re.compile(
        r"\b(?:htmlspecialchars|htmlentities|escapeshellarg|escapeshellcmd"
        r"|strip_tags|filter_var|mysqli_real_escape_string|addslashes"
        r"|escape_html|escapeHtml|html_escape|sanitize|prepare(?:Statement)?"
        r"|bind(?:Param|Value)|encodeURIComponent|encodeURI|urlencode"
        r"|textContent|createTextNode|appendChild"
        r"|esc_(?:html|attr|sql|js|url|textarea))\b"
    ),
    "has_dangerous_sink": re.compile(
        r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write"
        r"|dangerouslySetInnerHTML|eval\s*\(|exec\s*\(|system\s*\("
        r"|popen\s*\(|shell_exec\s*\(|passthru\s*\(|unserialize"
        r"|pickle\.loads?|os\.system|subprocess\.(?:call|Popen|run)"
        r"|Runtime\.getRuntime\(\)\.exec|new\s+Function)\b"
    ),
    "has_string_concat": re.compile(
        r"\+\s*['\"]|['\"]\s*\+|\.\s*\$|\$\{[^}]*\}"
        r"|f['\"][^'\"]*\{|sprintf\s*\(|format\s*\("
    ),
    "has_sql_keyword": re.compile(
        r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM|JOIN|INTO)\b",
        re.IGNORECASE,
    ),
    "has_path_traversal": re.compile(
        r"\.\./|\.\.\\\\|file_get_contents\s*\(\s*\$|fopen\s*\(\s*\$"
        r"|require(?:_once)?\s*\(\s*\$|include(?:_once)?\s*\(\s*\$"
    ),
}
_BINARY_NAMES = list(_PATTERNS.keys())


def binary_features(text: str) -> list[int]:
    if not isinstance(text, str):
        return [0] * len(_BINARY_NAMES)
    return [int(bool(p.search(text))) for p in _PATTERNS.values()]


# --------------------------------------------------------------
# 3. DATA-LASTING (med CWE) + LINJENIVÅ-EKSTRAKSJON
def load_pairs(path: Path) -> pd.DataFrame:
    conn = sqlite3.connect(str(path))
    df = pd.read_sql_query(
        """
        SELECT f.vuln_function, f.patch_function, c.cwe
        FROM functions f
        JOIN cve_commit cc
            ON f.repo_url = cc.repo_url AND f.commit_sha = cc.commit_sha
        JOIN cve c ON cc.cve_id = c.cve_id
        WHERE f.vuln_function IS NOT NULL AND f.patch_function IS NOT NULL
        """,
        conn,
    )
    conn.close()
    df = df.drop_duplicates(subset=["vuln_function", "patch_function"]).reset_index(drop=True)
    return df


def normalize_cwe(cwe):
    if not isinstance(cwe, str):
        return None
    m = re.search(r"CWE-\d+", cwe)
    return m.group(0) if m else None


def extract_with_context(vuln: str, patch: str, window: int = CONTEXT_WINDOW) -> list[dict]:
    """For hver endrede linje, returner linjen + N linjer kontekst over/under."""
    if not isinstance(vuln, str) or not isinstance(patch, str):
        return []
    v_lines = vuln.splitlines()
    p_lines = patch.splitlines()
    matcher = difflib.SequenceMatcher(a=v_lines, b=p_lines)
    out = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "delete"}:
            for i in range(i1, i2):
                s, e = max(0, i - window), min(len(v_lines), i + window + 1)
                out.append({"code": v_lines[i], "windowed": " \n ".join(v_lines[s:e]), "label": 0})
        if tag in {"replace", "insert"}:
            for j in range(j1, j2):
                s, e = max(0, j - window), min(len(p_lines), j + window + 1)
                out.append({"code": p_lines[j], "windowed": " \n ".join(p_lines[s:e]), "label": 1})
    return out


def build_dataset(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["cwe"] = df["cwe"].apply(normalize_cwe)
    df = df.dropna(subset=["cwe"]).reset_index(drop=True)

    rows = []
    for pair_id, row in df.iterrows():
        examples = extract_with_context(row["vuln_function"], row["patch_function"])
        seen = set()
        kept = []
        for ex in examples:
            n = normalize_line(ex["code"])
            if is_noise(n):
                continue
            key = (n, ex["label"])
            if key in seen:
                continue
            seen.add(key)
            kept.append({"pair_id": pair_id, "cwe": row["cwe"], "code": n,
                         "windowed": ex["windowed"], "label": ex["label"]})
        labels = {ex["label"] for ex in kept}
        if 0 in labels and 1 in labels:
            rows.extend(kept)

    out = pd.DataFrame(rows)
    if out.empty:
        raise ValueError("Ingen brukbare rader.")
    out = out.drop_duplicates(subset=["pair_id", "code", "label"]).copy()

    conflict = out.groupby("code")["label"].nunique().loc[lambda s: s > 1].index
    if len(conflict):
        out = out.loc[~out["code"].isin(conflict)].copy()

    rank = out.groupby(["code", "label"]).cumcount()
    out = out.loc[rank < MAX_ROWS_PER_CODE_LABEL].reset_index(drop=True)
    return out


# --------------------------------------------------------------
# 4. FEATURE-BYGGING (TF-IDF + binary, skalert)
def build_features(text_series: pd.Series, vec, fit: bool) -> sp.csr_matrix:
    if fit:
        word_X = vec.fit_transform(text_series)
    else:
        word_X = vec.transform(text_series)
    binary_arr = np.array([binary_features(t) for t in text_series], dtype=float)
    return sp.hstack([word_X, sp.csr_matrix(binary_arr)], format="csr")


# --------------------------------------------------------------
# 5. MODELLER (samme 15 som global-filen)
def get_models() -> dict:
    return {
        "Dummy": DummyClassifier(strategy="most_frequent", random_state=RANDOM_STATE),
        "LogisticRegression": LogisticRegression(max_iter=2000, class_weight="balanced"),
        "LinearSVC": LinearSVC(max_iter=2000, class_weight="balanced"),
        "RidgeClassifier": RidgeClassifier(class_weight="balanced"),
        "SGDClassifier": SGDClassifier(loss="hinge", max_iter=2000, random_state=RANDOM_STATE),
        "MultinomialNB": MultinomialNB(),
        "ComplementNB": ComplementNB(),
        "DecisionTree": DecisionTreeClassifier(max_depth=20, class_weight="balanced", random_state=RANDOM_STATE),
        "KNeighbors": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "RandomForest": RandomForestClassifier(n_estimators=200, max_depth=30, n_jobs=-1,
                                               class_weight="balanced", random_state=RANDOM_STATE),
        "ExtraTrees": ExtraTreesClassifier(n_estimators=200, max_depth=30, n_jobs=-1,
                                           class_weight="balanced", random_state=RANDOM_STATE),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=RANDOM_STATE),
        "HistGradientBoosting": HistGradientBoostingClassifier(max_iter=200, random_state=RANDOM_STATE),
        "AdaBoost": AdaBoostClassifier(n_estimators=100, random_state=RANDOM_STATE),
        "MLP": MLPClassifier(hidden_layer_sizes=(64,), max_iter=300,
                             random_state=RANDOM_STATE, early_stopping=True),
    }


# --------------------------------------------------------------
# 6. CROSS-VALIDATION (StratifiedGroupKFold på pair_id, fitter inni hver fold)
def cv_evaluate(model, sub: pd.DataFrame, n_folds: int) -> dict | None:
    n_pairs = sub["pair_id"].nunique()
    n_splits = min(n_folds, n_pairs // 2)
    if n_splits < 2:
        return None

    y = sub["label"].to_numpy()
    groups = sub["pair_id"].to_numpy()
    skf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)

    f1s, accs, precs, recs = [], [], [], []
    for tr, va in skf.split(np.zeros(len(sub)), y, groups=groups):
        vec = TfidfVectorizer(
            tokenizer=code_tokenizer, token_pattern=None,
            max_features=5000, ngram_range=(1, 2), min_df=2, sublinear_tf=True,
        )
        scaler = MaxAbsScaler()
        X_tr = scaler.fit_transform(build_features(sub.iloc[tr]["windowed"], vec, fit=True))
        X_va = scaler.transform(build_features(sub.iloc[va]["windowed"], vec, fit=False))

        m = clone(model)
        try:
            m.fit(X_tr, y[tr])
            yp = m.predict(X_va)
        except TypeError:
            m.fit(X_tr.toarray(), y[tr])
            yp = m.predict(X_va.toarray())
        f1s.append(f1_score(y[va], yp, average="macro", zero_division=0))
        accs.append(accuracy_score(y[va], yp))
        precs.append(precision_score(y[va], yp, average="macro", zero_division=0))
        recs.append(recall_score(y[va], yp, average="macro", zero_division=0))

    return {
        "f1_mean": float(np.mean(f1s)), "f1_std": float(np.std(f1s)),
        "acc_mean": float(np.mean(accs)),
        "prec_mean": float(np.mean(precs)),
        "rec_mean": float(np.mean(recs)),
    }


# --------------------------------------------------------------
# 7. PLOTS
def plot_best_per_cwe(best_df: pd.DataFrame, output_path: Path):
    df = best_df.sort_values("f1_mean", ascending=True)
    fig, ax = plt.subplots(figsize=(10, max(6, len(df) * 0.3)))
    labels = df["cwe"] + " (" + df["model"] + ")"
    ax.barh(labels, df["f1_mean"], color="darkgreen", edgecolor="black")
    ax.set_xlabel("Beste CV F1 per CWE")
    ax.set_title("Beste modell per CWE — linjenivå")
    ax.set_xlim(0, 1)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(output_path, dpi=120)
    plt.close(fig)


# --------------------------------------------------------------
# 8. HOVEDFUNKSJON
def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Laster datasett fra {DB_PATH}...")
    raw = load_pairs(DB_PATH)
    print(f"  Funksjons-par: {len(raw)}")
    df = build_dataset(raw)
    print(f"  Linjenivå-rader: {len(df)} på tvers av {df['cwe'].nunique()} CWE-er\n")

    cwe_counts = df.groupby("cwe")["pair_id"].nunique().sort_values(ascending=False)
    qualified = cwe_counts[cwe_counts >= MIN_PAIRS_PER_CWE].index.tolist()
    print(f"Kvalifiserte CWE-er (>= {MIN_PAIRS_PER_CWE} par): {len(qualified)}\n")

    models = get_models()
    all_results = []

    for cwe in qualified:
        sub = df[df["cwe"] == cwe].reset_index(drop=True)
        if sub["label"].nunique() < 2:
            continue
        print(f"=== {cwe} ({sub['pair_id'].nunique()} par, {len(sub)} linjer) ===")
        for name, model in models.items():
            t0 = time.time()
            try:
                metrics = cv_evaluate(model, sub, N_FOLDS)
                if metrics is None:
                    continue
                elapsed = time.time() - t0
                all_results.append({
                    "cwe": cwe, "model": name,
                    "n_pairs": int(sub["pair_id"].nunique()),
                    "n_samples": len(sub),
                    **metrics, "time_sec": round(elapsed, 1),
                })
                print(f"  {name:<22} F1={metrics['f1_mean']:.3f}±{metrics['f1_std']:.3f}  "
                      f"Acc={metrics['acc_mean']:.3f}  ({elapsed:.1f}s)")
            except Exception as e:
                print(f"  {name:<22} FEILET: {e}")
        print()

    results_df = pd.DataFrame(all_results)
    results_df.to_csv(OUTPUT_DIR / "results.csv", index=False)

    # Beste modell per CWE
    best = (results_df.loc[results_df.groupby("cwe")["f1_mean"].idxmax()]
                      .sort_values("f1_mean", ascending=False)
                      .reset_index(drop=True))
    best.to_csv(OUTPUT_DIR / "best_per_cwe.csv", index=False)
    plot_best_per_cwe(best, OUTPUT_DIR / "best_per_cwe.png")

    print("=" * 70)
    print("BESTE MODELL PER CWE (sortert på CV F1)")
    print("=" * 70)
    print(best[["cwe", "model", "n_pairs", "n_samples", "f1_mean", "f1_std", "acc_mean"]]
          .to_string(index=False))

    print(f"\nAlle resultater: {OUTPUT_DIR}/results.csv")
    print(f"Beste per CWE: {OUTPUT_DIR}/best_per_cwe.csv")
    print(f"Sammenligningsplot: {OUTPUT_DIR}/best_per_cwe.png")


if __name__ == "__main__":
    main()
