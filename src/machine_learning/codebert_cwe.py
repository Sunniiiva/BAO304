# Per-CWE CodeBERT-based vulnerability classifier (Google Colab)
# ===============================================================
# Fine-tunes microsoft/codebert-base ONCE per qualified CWE on line-level
# diff samples to predict vulnerable (0) vs patched (1).
#
# How to use this file in Colab:
#   1. Open a new notebook on https://colab.research.google.com
#   2. Runtime → Change runtime type → T4 GPU (preferably A100/V100 if Pro)
#   3. Upload your cve_commits.db file (or put it on Google Drive)
#   4. Copy each "# %%" block into a separate Colab cell and run in order
#
# IMPORTANT — runtime warning
# ----------------------------
# Fine-tuning CodeBERT for ~80 CWEs is computationally expensive.
# On a T4 GPU, expect ~5-15 minutes per CWE × ~80 CWEs = ~7-20 hours total.
# To make this practical:
#   - Set MIN_PAIRS_PER_CWE higher (e.g., 50) to skip very small CWEs
#   - Reduce EPOCHS to 2 if time-limited
#   - Use Colab Pro+ for longer GPU sessions and faster A100/V100 GPUs
#   - The script saves results CWE-by-CWE so you can resume after disconnect

# ============================================================
# %% Cell 1 — Install dependencies
# ============================================================
# !pip install -q transformers==4.41.0 torch pandas scikit-learn matplotlib

# ============================================================
# %% Cell 2 — Mount Google Drive (recommended for resumable runs)
# ============================================================
# from google.colab import drive
# drive.mount('/content/drive')
# DB_PATH = "/content/drive/MyDrive/cve_commits.db"
# OUTPUT_DIR = "/content/drive/MyDrive/codebert_per_cwe_output"

# Alternative: upload directly
# from google.colab import files
# files.upload()  # cve_commits.db
# DB_PATH = "/content/cve_commits.db"
# OUTPUT_DIR = "/content/codebert_per_cwe_output"

# ============================================================
# %% Cell 3 — Imports and configuration
# ============================================================
import difflib
import os
import re
import sqlite3
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from torch.utils.data import DataLoader, Dataset
from transformers import (
    AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup,
)

warnings.filterwarnings("ignore")

# CONFIG — adjust to your environment
DB_PATH = "/content/cve_commits.db"
OUTPUT_DIR = Path("/content/codebert_per_cwe_output")
MODEL_NAME = "microsoft/codebert-base"

CONTEXT_WINDOW = 3
MAX_ROWS_PER_CODE_LABEL = 5
MAX_LENGTH = 256
BATCH_SIZE = 16
LEARNING_RATE = 2e-5
EPOCHS = 3
N_FOLDS = 5
RANDOM_STATE = 42

# Skip CWEs with fewer than this many pairs (raise to speed up)
MIN_PAIRS_PER_CWE = 25

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# %% Cell 4 — Line-level extraction (with CWE join)
# ============================================================
_TRIVIAL = {"{", "}", "(", ")", "[", "]", ";", ",", "else", "try",
            "finally", "pass", "break", "continue", "default", "case"}
_COMMENT = ("#", "//", "/*", "*", "*/", "--")
_IMPORT = re.compile(r"^(from|import|using|package|namespace)\b")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|==|!=|<=|>=|&&|\|\||[-+*/%<>]=")


def normalize_line(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def is_noise(line: str) -> bool:
    if not line:
        return True
    if line in _TRIVIAL or line.startswith(_COMMENT) or _IMPORT.match(line):
        return True
    if len(line) < 4 or len(line) > 300:
        return True
    if re.fullmatch(r"[\W_]+", line):
        return True
    return len(_TOKEN.findall(line)) < 2


def normalize_cwe(cwe):
    if not isinstance(cwe, str):
        return None
    m = re.search(r"CWE-\d+", cwe)
    return m.group(0) if m else None


def extract_with_context(vuln, patch, window=CONTEXT_WINDOW):
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


def load_pairs(path):
    conn = sqlite3.connect(str(path))
    df = pd.read_sql_query(
        """SELECT f.vuln_function, f.patch_function, c.cwe
           FROM functions f
           JOIN cve_commit cc ON f.repo_url = cc.repo_url AND f.commit_sha = cc.commit_sha
           JOIN cve c ON cc.cve_id = c.cve_id
           WHERE f.vuln_function IS NOT NULL AND f.patch_function IS NOT NULL""",
        conn,
    )
    conn.close()
    return df.drop_duplicates(subset=["vuln_function", "patch_function"]).reset_index(drop=True)


def build_dataset(df):
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
        raise ValueError("No usable rows.")
    out = out.drop_duplicates(subset=["pair_id", "code", "label"]).copy()
    conflict = out.groupby("code")["label"].nunique().loc[lambda s: s > 1].index
    if len(conflict):
        out = out.loc[~out["code"].isin(conflict)].copy()
    rank = out.groupby(["code", "label"]).cumcount()
    return out.loc[rank < MAX_ROWS_PER_CODE_LABEL].reset_index(drop=True)


# ============================================================
# %% Cell 5 — Load data and find qualified CWEs
# ============================================================
print(f"Loading from {DB_PATH}...")
raw = load_pairs(DB_PATH)
print(f"  Function pairs: {len(raw)}")
df = build_dataset(raw)
print(f"  Line-level samples: {len(df)} across {df['cwe'].nunique()} CWEs")

cwe_counts = df.groupby("cwe")["pair_id"].nunique().sort_values(ascending=False)
qualified = cwe_counts[cwe_counts >= MIN_PAIRS_PER_CWE].index.tolist()
print(f"\nQualified CWEs (>= {MIN_PAIRS_PER_CWE} pairs): {len(qualified)}")
print(f"Estimated total runtime: ~{len(qualified) * 8 // 60}-{len(qualified) * 15 // 60} hours on T4 GPU")

# ============================================================
# %% Cell 6 — PyTorch dataset wrapper
# ============================================================
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)


class CodeDataset(Dataset):
    def __init__(self, texts, labels):
        self.texts = list(texts)
        self.labels = list(labels)

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        encoding = tokenizer(
            self.texts[idx],
            truncation=True, padding="max_length",
            max_length=MAX_LENGTH, return_tensors="pt",
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


# ============================================================
# %% Cell 7 — Train/evaluate one fold (per-CWE)
# ============================================================
def train_one_fold(train_df, val_df):
    train_loader = DataLoader(
        CodeDataset(train_df["windowed"], train_df["label"]),
        batch_size=BATCH_SIZE, shuffle=True, num_workers=2,
    )
    val_loader = DataLoader(
        CodeDataset(val_df["windowed"], val_df["label"]),
        batch_size=BATCH_SIZE, shuffle=False, num_workers=2,
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, num_labels=2,
    ).to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE)
    total_steps = len(train_loader) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=int(0.1 * total_steps), num_training_steps=total_steps,
    )

    for epoch in range(EPOCHS):
        model.train()
        for batch in train_loader:
            optimizer.zero_grad()
            out = model(
                input_ids=batch["input_ids"].to(device),
                attention_mask=batch["attention_mask"].to(device),
                labels=batch["labels"].to(device),
            )
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

    model.eval()
    preds, trues = [], []
    with torch.no_grad():
        for batch in val_loader:
            out = model(
                input_ids=batch["input_ids"].to(device),
                attention_mask=batch["attention_mask"].to(device),
            )
            preds.extend(out.logits.argmax(dim=-1).cpu().numpy())
            trues.extend(batch["labels"].numpy())

    # Free GPU memory before next fold
    del model
    torch.cuda.empty_cache()
    return np.array(trues), np.array(preds)


# ============================================================
# %% Cell 8 — Per-CWE training loop with resume support
# ============================================================
results_path = OUTPUT_DIR / "codebert_per_cwe_results.csv"

# Resume support: load existing results so we don't repeat finished CWEs
if results_path.exists():
    existing = pd.read_csv(results_path)
    done_cwes = set(existing["cwe"].unique())
    all_results = existing.to_dict("records")
    print(f"Resuming — {len(done_cwes)} CWEs already done. Skipping them.")
else:
    done_cwes = set()
    all_results = []

for cwe in qualified:
    if cwe in done_cwes:
        continue

    sub = df[df["cwe"] == cwe].reset_index(drop=True)
    if sub["label"].nunique() < 2:
        print(f"Skipping {cwe}: only one class present")
        continue

    n_pairs = sub["pair_id"].nunique()
    n_samples = len(sub)
    n_splits = min(N_FOLDS, n_pairs // 2)
    if n_splits < 2:
        print(f"Skipping {cwe}: too few pairs ({n_pairs}) for cross-validation")
        continue

    print(f"\n=== {cwe} ({n_pairs} pairs, {n_samples} samples) ===")
    cwe_t0 = time.time()
    skf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)

    fold_f1s, fold_accs, fold_precs, fold_recs = [], [], [], []
    for fold, (tr, va) in enumerate(skf.split(sub, sub["label"], groups=sub["pair_id"]), start=1):
        train_df = sub.iloc[tr].reset_index(drop=True)
        val_df = sub.iloc[va].reset_index(drop=True)
        try:
            y_true, y_pred = train_one_fold(train_df, val_df)
            fold_f1s.append(f1_score(y_true, y_pred, average="macro", zero_division=0))
            fold_accs.append(accuracy_score(y_true, y_pred))
            fold_precs.append(precision_score(y_true, y_pred, average="macro", zero_division=0))
            fold_recs.append(recall_score(y_true, y_pred, average="macro", zero_division=0))
        except Exception as e:
            print(f"  Fold {fold} FAILED: {e}")

    if not fold_f1s:
        continue

    elapsed = time.time() - cwe_t0
    row = {
        "cwe": cwe, "n_pairs": int(n_pairs), "n_samples": int(n_samples),
        "f1_mean": float(np.mean(fold_f1s)), "f1_std": float(np.std(fold_f1s)),
        "acc_mean": float(np.mean(fold_accs)),
        "prec_mean": float(np.mean(fold_precs)),
        "rec_mean": float(np.mean(fold_recs)),
        "time_sec": round(elapsed, 1),
    }
    all_results.append(row)
    print(f"  CodeBERT: F1={row['f1_mean']:.4f}±{row['f1_std']:.4f}  "
          f"Acc={row['acc_mean']:.4f}  ({elapsed/60:.1f} min)")

    # Save after each CWE so we can resume if disconnected
    pd.DataFrame(all_results).to_csv(results_path, index=False)

# ============================================================
# %% Cell 9 — Final summary
# ============================================================
results_df = pd.DataFrame(all_results).sort_values("f1_mean", ascending=False).reset_index(drop=True)
print("\n" + "=" * 70)
print("RESULTS — CodeBERT per-CWE classifier")
print("=" * 70)
print(results_df.to_string(index=False))
print(f"\nMean F1 across CWEs:    {results_df['f1_mean'].mean():.4f}")
print(f"Best CWE:               {results_df.iloc[0]['cwe']} (F1={results_df.iloc[0]['f1_mean']:.4f})")
print(f"Worst CWE:              {results_df.iloc[-1]['cwe']} (F1={results_df.iloc[-1]['f1_mean']:.4f})")
print(f"\nResults saved to: {results_path}")

# ============================================================
# %% Cell 10 — Optional: download results back to local
# ============================================================
# from google.colab import files
# files.download(str(results_path))
