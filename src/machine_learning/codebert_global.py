# Global CodeBERT-based vulnerability classifier (Google Colab)
# =============================================================
# Fine-tunes microsoft/codebert-base on line-level diff samples to predict
# vulnerable (0) vs patched (1) — replaces TF-IDF + classical ML with a
# pretrained code transformer.
#
# How to use this file in Colab:
#   1. Open a new notebook on https://colab.research.google.com
#   2. Runtime → Change runtime type → T4 GPU (or better)
#   3. Upload your cve_commits.db file (or put it on Google Drive)
#   4. Copy each "# %%" block into a separate Colab cell and run in order
#
# Expected time on a T4 GPU: ~30–60 min for 3 epochs on full dataset.

# ============================================================
# %% Cell 1 — Install dependencies
# ============================================================
# !pip install -q transformers==4.41.0 torch pandas scikit-learn matplotlib

# ============================================================
# %% Cell 2 — Mount Google Drive (optional, if DB is on Drive)
# ============================================================
# from google.colab import drive
# drive.mount('/content/drive')
# DB_PATH = "/content/drive/MyDrive/cve_commits.db"

# Alternative: upload directly to Colab's local filesystem
# from google.colab import files
# files.upload()  # then choose cve_commits.db
# DB_PATH = "/content/cve_commits.db"

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
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from torch.utils.data import DataLoader, Dataset
from transformers import (
    AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup,
)

warnings.filterwarnings("ignore")

# CONFIG — adjust paths and hyperparameters
DB_PATH = "/content/cve_commits.db"        # path to cve_commits.db in Colab
OUTPUT_DIR = Path("/content/output_global")
MODEL_NAME = "microsoft/codebert-base"

CONTEXT_WINDOW = 3
MAX_ROWS_PER_CODE_LABEL = 5
MAX_LENGTH = 256                            # token cap per sample (256 fits 7-line snippets)
BATCH_SIZE = 16
LEARNING_RATE = 2e-5
EPOCHS = 3
N_FOLDS = 5
RANDOM_STATE = 42

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# %% Cell 4 — Line-level extraction from diff (same logic as ml_line_level.py)
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
        """SELECT vuln_function, patch_function FROM functions
           WHERE vuln_function IS NOT NULL AND patch_function IS NOT NULL""",
        conn,
    )
    conn.close()
    return df.drop_duplicates(subset=["vuln_function", "patch_function"]).reset_index(drop=True)


def build_dataset(df):
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
            kept.append({"pair_id": pair_id, "code": n, "windowed": ex["windowed"], "label": ex["label"]})
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
# %% Cell 5 — Load and prepare data
# ============================================================
print(f"Loading from {DB_PATH}...")
raw = load_pairs(DB_PATH)
print(f"  Function pairs: {len(raw)}")
df = build_dataset(raw)
print(f"  Line-level samples: {len(df)} ({df['label'].value_counts().to_dict()})")
print(f"  Unique pairs after filtering: {df['pair_id'].nunique()}")

# ============================================================
# %% Cell 6 — PyTorch dataset wrapper for CodeBERT
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
# %% Cell 7 — Train/evaluate CodeBERT for one fold
# ============================================================
def train_one_fold(train_df, val_df, fold_num):
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
        total_loss = 0
        t0 = time.time()
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
            total_loss += out.loss.item()
        print(f"  Fold {fold_num} Epoch {epoch+1}/{EPOCHS}  "
              f"loss={total_loss/len(train_loader):.4f}  ({time.time()-t0:.0f}s)")

    # Evaluate
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
    return np.array(trues), np.array(preds), model


# ============================================================
# %% Cell 8 — 5-fold cross-validation
# ============================================================
print(f"\nTraining CodeBERT with {N_FOLDS}-fold StratifiedGroupKFold CV...")
y = df["label"].to_numpy()
groups = df["pair_id"].to_numpy()
skf = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=RANDOM_STATE)

fold_results = []
all_true, all_pred = [], []
best_model = None
best_f1 = 0

for fold, (tr_idx, va_idx) in enumerate(skf.split(df, y, groups=groups), start=1):
    print(f"\n=== Fold {fold}/{N_FOLDS} ===")
    train_df = df.iloc[tr_idx].reset_index(drop=True)
    val_df = df.iloc[va_idx].reset_index(drop=True)

    y_true, y_pred, model = train_one_fold(train_df, val_df, fold)

    f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    rec = recall_score(y_true, y_pred, average="macro", zero_division=0)

    fold_results.append({"fold": fold, "f1": f1, "acc": acc, "prec": prec, "rec": rec})
    all_true.extend(y_true)
    all_pred.extend(y_pred)
    print(f"  Fold {fold} F1={f1:.4f}  Acc={acc:.4f}  Prec={prec:.4f}  Rec={rec:.4f}")

    if f1 > best_f1:
        best_f1 = f1
        best_model = model

# ============================================================
# %% Cell 9 — Aggregate results and save
# ============================================================
results_df = pd.DataFrame(fold_results)
print("\n" + "=" * 60)
print("RESULTS — CodeBERT global classifier")
print("=" * 60)
print(results_df.to_string(index=False))
print(f"\nMean F1:        {results_df['f1'].mean():.4f} ± {results_df['f1'].std():.4f}")
print(f"Mean Accuracy:  {results_df['acc'].mean():.4f} ± {results_df['acc'].std():.4f}")
print(f"Mean Precision: {results_df['prec'].mean():.4f}")
print(f"Mean Recall:    {results_df['rec'].mean():.4f}")

print("\nClassification report (out-of-fold):")
print(classification_report(all_true, all_pred, target_names=["vulnerable", "patched"]))
print("Confusion matrix:")
print(confusion_matrix(all_true, all_pred))

results_df.to_csv(OUTPUT_DIR / "codebert_global_results.csv", index=False)
pd.DataFrame({"true": all_true, "pred": all_pred}).to_csv(
    OUTPUT_DIR / "codebert_global_predictions.csv", index=False,
)

# Save best model + tokenizer
best_model.save_pretrained(OUTPUT_DIR / "best_model")
tokenizer.save_pretrained(OUTPUT_DIR / "best_model")
print(f"\nBest model saved to: {OUTPUT_DIR / 'best_model'}")
print(f"Results saved to: {OUTPUT_DIR / 'codebert_global_results.csv'}")

# ============================================================
# %% Cell 10 — Optional: download results back to local
# ============================================================
# from google.colab import files
# files.download(str(OUTPUT_DIR / "codebert_global_results.csv"))
# files.download(str(OUTPUT_DIR / "codebert_global_predictions.csv"))
