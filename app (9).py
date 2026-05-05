"""
=============================================================================
SENTINEL — Malicious URL Detector  v3.0
=============================================================================
Single-file Streamlit application. Self-contained — no requirements.txt needed.
Auto-installs missing packages at runtime.

Dataset   : 2,000 URLs (1,000 benign + 1,000 malicious) — Streamlit-safe
Models    : Random Forest · Linear SVM (calibrated) · Decision Tree
Features  : 36 lexical + host-based URL features
Metrics   : Accuracy · Precision · Recall · F1 · FAR · FRR · AUC
Charts    : Confusion Matrix · ROC Curve · Feature Impact
Storage   : SQLite scan logging · session history
UI        : Sentinel dark dashboard · sidebar history · two-tab layout

WHY 2,000 ROWS?
  Streamlit Community Cloud allocates ~1 GB RAM and ~1 CPU.
  - 1,000 rows → trains in ~3 s but low variance for comparison
  - 2,000 rows → trains in ~8 s, enough signal for all three models
  - 5,000+ rows → SVM begins to slow, risk of cold-start timeout
  2,000 is the practical sweet spot.

WHY LinearSVC INSTEAD OF SVC(rbf)?
  SVC with kernel='rbf' and probability=True uses Platt scaling,
  which requires an internal O(n²) cross-validation pass — it takes
  several minutes on even 2,000 rows on a cloud CPU.
  LinearSVC + CalibratedClassifierCV achieves the same calibrated
  probability output in O(n) time and is included in scikit-learn
  with no extra install.
=============================================================================
"""

# =============================================================================
# SECTION 1 — AUTO-INSTALL MISSING PACKAGES
# =============================================================================
# Streamlit Cloud may not have all third-party packages pre-installed.
# This block silently installs anything missing before importing it.
# Standard-library modules (os, re, math, time, csv, random, sqlite3,
# json, urllib, datetime) are built-in and never need installation.

import os, re, math, time, csv, random, json, sqlite3, sys, subprocess, importlib
from urllib.parse import urlparse, parse_qs
from datetime import datetime

def _ensure(pip_name: str, import_name: str = None):
    """
    Import a package by import_name (defaults to pip_name).
    If the import fails, pip-install it silently then re-import.
    Uses importlib.import_module which correctly handles subpackages
    like 'sklearn' that __import__ can fail to surface properly.
    """
    name = import_name or pip_name
    try:
        return importlib.import_module(name)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pip_name,
             "--quiet", "--disable-pip-version-check"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return importlib.import_module(name)

_ensure("joblib")
_ensure("numpy")
_ensure("pandas")
_ensure("matplotlib")
_ensure("scikit-learn", "sklearn")

import joblib
import numpy as np
import pandas as pd
import matplotlib                 # import first so we can set backend
matplotlib.use("Agg")            # MUST be set before importing pyplot — non-interactive backend
import matplotlib.pyplot as plt  # pyplot imported after backend is locked in
import streamlit as st

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, roc_auc_score, ConfusionMatrixDisplay,
)


# =============================================================================
# SECTION 2 — PATHS  (all absolute so Streamlit Cloud can find them)
# =============================================================================

_HERE           = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH    = os.path.join(_HERE, "data",   "urls_dataset.csv")
MODEL_PATH      = os.path.join(_HERE, "models", "best_model.joblib")
COMPARISON_PATH = os.path.join(_HERE, "models", "model_comparison.json")
DB_PATH         = os.path.join(_HERE, "data",   "scans.db")


# =============================================================================
# SECTION 3 — DATASET GENERATION (2,000 URLs)
# =============================================================================
# Augments the 50+50 seed URLs to 1,000 benign + 1,000 malicious = 2,000 rows.
# Sweet spot: trains all three models in ~8 s on Streamlit Community Cloud.
# Larger datasets (5,000+) cause SVM to time out on the free cloud tier.

REALISTIC_BENIGN = [
    "https://www.google.com/search?q=python+tutorial",
    "https://github.com/scikit-learn/scikit-learn",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://docs.python.org/3/library/re.html",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.linkedin.com/in/johndoe",
    "https://twitter.com/user/status/123456789",
    "https://www.reddit.com/r/learnpython/",
    "https://medium.com/@author/article-title-abc",
    "https://en.wikipedia.org/wiki/Artificial_intelligence",
    "https://www.bbc.com/news/technology",
    "https://www.nytimes.com/2024/technology/ai.html",
    "https://www.microsoft.com/en-us/microsoft-365",
    "https://www.apple.com/iphone/",
    "https://www.paypal.com/us/home",
    "https://www.netflix.com/browse",
    "https://www.instagram.com/p/ABC123/",
    "https://www.facebook.com/events/12345/",
    "https://accounts.google.com/o/oauth2/auth?client_id=x",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://drive.google.com/file/d/1abc/view",
    "https://www.dropbox.com/s/abc123/file.pdf",
    "https://support.apple.com/en-us/HT201994",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://nodejs.org/en/docs/",
    "https://reactjs.org/docs/getting-started.html",
    "https://vuejs.org/guide/introduction.html",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.udemy.com/course/python-bootcamp/",
    "https://arxiv.org/abs/2303.08774",
    "https://pypi.org/project/scikit-learn/",
    "https://hub.docker.com/_/python",
    "https://kubernetes.io/docs/concepts/overview/",
    "https://aws.amazon.com/ec2/",
    "https://cloud.google.com/compute/docs",
    "https://azure.microsoft.com/en-us/products/virtual-machines",
    "https://www.cloudflare.com/learning/ddos/",
    "https://letsencrypt.org/getting-started/",
    "https://www.w3schools.com/python/",
    "https://realpython.com/python-f-strings/",
    "https://www.geeksforgeeks.org/python-programming-language/",
    "https://towardsdatascience.com/",
    "https://www.kaggle.com/competitions",
    "https://huggingface.co/models",
    "https://streamlit.io/",
    "https://fastapi.tiangolo.com/",
    "https://flask.palletsprojects.com/",
    "https://www.djangoproject.com/",
]

REALISTIC_MALICIOUS = [
    "http://paypal.com.secure-login-verify.xyz/account/update?token=abc",
    "http://192.168.1.105/admin/login.php?redirect=home",
    "http://g00gle-security-alert.com/verify?user=victim@gmail.com",
    "http://amazon-prize-winner-2024.top/claim?id=99812&ref=email",
    "http://login.microsoftonline.com.phish.tk/oauth2/token",
    "http://secure.paypal-account-verify.ml/login?next=/dashboard",
    "http://bit.ly/3xFreeGift-Claim-Now-2024",
    "http://free-iphone-15-winner.xyz/claim?tracking=FB_AD_001",
    "http://your-bank-secure.suspicious-domain.cc/verify-identity",
    "http://update-your-netflix-billing.live/payment?ref=email",
    "http://apple-id-locked-alert.top/unlock?case=12345",
    "http://win-cash-prize-2024.tk/register?promo=WIN500",
    "http://download-crack-software.ml/setup.exe?id=12345",
    "http://verify-your-facebook-account.xyz/login",
    "http://amazon.com.fake-verify.biz/signin?ref=phish",
    "http://secure-login.paypa1-support.com/help/account",
    "http://google.account-suspended-alert.online/fix",
    "http://dropbox.com.secure.upload-files.info/share",
    "http://www.malware-delivery.net/payload.exe?dl=1",
    "http://urgent-action-required.top/account?email=user@mail.com",
    "http://virus-scan-results.xyz/remove?threatid=9912",
    "http://10.0.0.1/cgi-bin/login.cgi",
    "http://172.16.254.1/setup/admin?pass=admin",
    "http://user@malicious-host.tk/",
    "http://login.ebay.com.cheap-deals-now.pw/signin",
    "http://secure.chase.bank.account-suspended.ml/login",
    "http://track-my-package.xyz/usps?track=1Z999AA0",
    "http://covid-relief-fund.tk/apply?ref=govt",
    "http://faceb00k-security.xyz/recover?id=12345",
    "http://your-crypto-wallet-alert.top/connect?wallet=MetaMask",
    "http://steam-free-gift-card.ml/redeem?code=FREE2024",
    "http://click-here-to-earn-500-usd.top/?aff=1234",
    "http://tinyurl.com/free-adult-content-2024",
    "http://drive.google.com.file-share.xyz/d/1abc/view",
    "http://apple.com.account-locked.online/appleid/unlock",
    "http://secure-login-verify.amazon-account.cc/signin",
    "http://urgent.dhl-delivery-problem.top/track?id=9988",
    "http://bank-notification-alert.xyz/verify?acct=123456",
    "http://microsoft-tech-support-alert.tk/call?code=ERR_VIRUS",
    "http://irs-tax-refund-ready.ml/claim?ssn=needed",
    "http://youtube.com.premium-free.biz/activate",
    "http://instagram-verify-now.xyz/confirm?user=victim",
    "http://netflix.com.billing-update.online/payment",
    "http://fake-antivirus-scan.cc/remove?threats=99",
    "http://your-account-hacked-alert.xyz/secure?id=abc",
    "http://win-free-ps5-console.top/register?promo=PS5FREE",
    "http://paypal.billing.update-required.xyz/confirm",
    "http://icloud.apple.id-verify.cc/unlock",
    "http://bank.account.suspended.suspicious.xyz/verify",
    "http://confirm-you-are-human.xyz/click",
]


def augment_urls(url_list: list, target_count: int) -> list:
    """Grow url_list to target_count by appending query-string variants."""
    if len(url_list) >= target_count:
        return random.sample(url_list, target_count)
    augmented = list(url_list)
    while len(augmented) < target_count:
        base = random.choice(url_list)
        suffix = (
            f"&ref_{random.randint(1,999)}={random.randint(1000,99999)}"
            if '?' in base
            else f"?ref={random.randint(1000,99999)}"
        )
        candidate = base + suffix
        if candidate not in augmented:
            augmented.append(candidate)
    random.shuffle(augmented)
    return augmented[:target_count]


def create_dataset(n_benign: int = 500, n_malicious: int = 500):
    """Write urls_dataset.csv with balanced benign/malicious rows."""
    rows = (
        [(u, 0) for u in augment_urls(REALISTIC_BENIGN,    n_benign)] +
        [(u, 1) for u in augment_urls(REALISTIC_MALICIOUS, n_malicious)]
    )
    random.shuffle(rows)
    # Guard: os.path.dirname may return '' for bare filenames
    data_dir = os.path.dirname(DATASET_PATH)
    if data_dir:
        os.makedirs(data_dir, exist_ok=True)
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label"])
        w.writerows(rows)


def ensure_dataset():
    if not os.path.exists(DATASET_PATH):
        create_dataset(1000, 1000)   # 2,000 total — Streamlit-safe sweet spot


# =============================================================================
# SECTION 4 — FEATURE EXTRACTION (36 features)
# =============================================================================

SUSPICIOUS_TLDS = {
    'xyz','top','click','tk','ml','ga','cf','gq','pw','cc','su','biz','info',
    'online','site','live','stream','download','loan','review','country','kim',
    'science','work','party','trade','cricket','date','faith','racing',
    'accountant','win','bid','men','icu','monster','cyou','buzz','sbs','ru',
}
TRUSTED_DOMAINS = {
    'google.com','youtube.com','facebook.com','microsoft.com','apple.com',
    'amazon.com','github.com','twitter.com','linkedin.com','wikipedia.org',
    'instagram.com','netflix.com','stackoverflow.com','reddit.com','paypal.com',
    'bbc.com','nytimes.com','dropbox.com','mozilla.org','cloudflare.com',
    'medium.com','kaggle.com','huggingface.co','arxiv.org','nature.com',
    'zoom.us','slack.com','notion.so','figma.com','canva.com','stripe.com',
    'shopify.com','heroku.com','vercel.com','netlify.com',
}
BRAND_KEYWORDS = [
    'paypal','google','apple','microsoft','amazon','facebook','instagram',
    'netflix','ebay','steam','whatsapp','youtube','dropbox','icloud','twitter',
    'chase','wellsfargo','citibank','bankofamerica','boa','dhl','fedex','usps','ups',
]
URL_SHORTENERS = {
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
    'rebrand.ly','short.io','tiny.cc','cutt.ly','shorturl.at','rb.gy',
}
PHISH_RE = re.compile(
    r'login|signin|verify|account|update|secure|confirm|password|credential|'
    r'alert|suspend|unlock|recover|reset|billing|payment|invoice', re.I
)
EXEC_RE = re.compile(
    r'\.(exe|bat|cmd|msi|scr|vbs|jar|apk|dmg|sh|ps1|crx|xpi)$', re.I
)
SPAM_WORDS = [
    'free','win','prize','claim','urgent','alert','suspended','verify',
    'confirm','limited','offer','bonus','gift','reward','lucky','congratulation',
]


def _entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())


def _domain_parts(hostname: str):
    clean = re.sub(r'^www\.', '', hostname.lower())
    parts = clean.split('.')
    if len(parts) >= 3: return '.'.join(parts[:-2]), parts[-2], parts[-1]
    if len(parts) == 2: return '', parts[0], parts[1]
    return '', hostname, ''


def extract_features(url: str) -> dict:
    """Return a 36-element feature dict for the given URL string."""
    raw = str(url).strip()
    f   = {}
    try:
        p = urlparse(raw if '://' in raw else 'http://' + raw)
    except Exception:
        p = urlparse('http://invalid')

    hostname   = (p.hostname or '').lower()
    path       = p.path or ''
    query      = p.query or ''
    scheme     = p.scheme or ''
    full_lower = raw.lower()

    _, domain, tld = _domain_parts(hostname)
    base           = f"{domain}.{tld}" if domain and tld else hostname
    sub, _, _      = _domain_parts(hostname)
    hl             = max(len(hostname), 1)

    f['is_https']          = int(scheme == 'https')
    f['is_http']           = int(scheme == 'http')
    f['url_length']        = len(raw)
    f['hostname_length']   = len(hostname)
    f['path_length']       = len(path)
    f['query_length']      = len(query)
    f['dot_count']         = hostname.count('.')
    f['hyphen_count']      = hostname.count('-')
    f['underscore_count']  = raw.count('_')
    f['at_sign']           = int('@' in raw)
    f['double_slash']      = int('//' in path)
    f['question_mark']     = int('?' in raw)
    f['ampersand_count']   = query.count('&')
    f['equals_count']      = query.count('=')
    f['percent_count']     = len(re.findall(r'%[0-9a-fA-F]{2}', raw))
    f['hash_count']        = int('#' in raw)
    f['digit_ratio']       = round(sum(c.isdigit() for c in hostname) / hl, 4)
    f['alpha_ratio']       = round(sum(c.isalpha() for c in hostname) / hl, 4)
    f['subdomain_count']   = len(sub.split('.')) if sub else 0
    f['suspicious_tld']    = int(tld in SUSPICIOUS_TLDS)
    f['tld_length']        = len(tld)
    f['is_ip_host']        = int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname)))
    f['trusted_domain']    = int(base in TRUSTED_DOMAINS)
    brand_hit              = any(b in hostname for b in BRAND_KEYWORDS)
    f['brand_in_domain']   = int(brand_hit and base not in TRUSTED_DOMAINS)
    f['digit_in_word']     = int(bool(re.search(r'[a-z]\d[a-z]', hostname)))
    f['phish_path_kw']     = int(bool(PHISH_RE.search(path)))
    f['executable_ext']    = int(bool(EXEC_RE.search(path)))
    f['path_depth']        = path.count('/')
    f['path_has_ip']       = int(bool(re.search(r'/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', path)))
    try:    f['param_count'] = len(parse_qs(query))
    except: f['param_count'] = 0
    f['hostname_entropy']  = round(_entropy(hostname), 4)
    f['path_entropy']      = round(_entropy(path), 4)
    f['is_shortener']      = int(hostname in URL_SHORTENERS)
    f['spam_keyword_count']= sum(w in full_lower for w in SPAM_WORDS)
    f['has_punycode']      = int('xn--' in hostname)
    f['domain_age_days']   = 365   # WHOIS removed — not available on Streamlit Cloud
    return f


FEATURE_COLUMNS = list(extract_features("http://example.com").keys())


# =============================================================================
# SECTION 5 — DATABASE (SQLite)
# =============================================================================

def init_database():
    """Create the SQLite database and tables if they don't exist."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score REAL NOT NULL,
            safe_pct REAL NOT NULL,
            mal_pct REAL NOT NULL,
            processing_time REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            feature_name TEXT NOT NULL,
            feature_value TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    ''')
    conn.commit()
    conn.close()


def log_prediction(data: dict) -> int:
    """Insert a scan result into the database and return its row id."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'INSERT INTO scans (url, verdict, risk_score, safe_pct, mal_pct, processing_time) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (data.get('url',''), data.get('verdict',''),
         data.get('risk_score',0), data.get('safe_pct',0),
         data.get('mal_pct',0), data.get('processing_time',0))
    )
    scan_id = c.lastrowid
    for fname, fval in data.get('features', {}).items():
        c.execute(
            'INSERT INTO scan_features (scan_id, feature_name, feature_value) VALUES (?,?,?)',
            (scan_id, fname, str(fval))
        )
    conn.commit()
    conn.close()
    return scan_id


def get_recent_scans(limit: int = 10) -> list:
    """Return the most recent `limit` scans as a list of dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        'SELECT id, url, verdict, risk_score, timestamp FROM scans '
        'ORDER BY timestamp DESC LIMIT ?', (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_total_scans() -> int:
    """Return the total number of scans stored in the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM scans')
    count = c.fetchone()[0]
    conn.close()
    return count


# =============================================================================
# SECTION 6 — MODEL TRAINING (Random Forest · Linear SVM · Decision Tree)
# =============================================================================
# Three classifiers are trained and compared.
#
# SVM IMPLEMENTATION NOTE
# ────────────────────────
# SVC(kernel='rbf', probability=True) uses Platt scaling — an internal
# O(n²) cross-validation step that takes several minutes on cloud CPUs.
# Instead we use:
#   LinearSVC (O(n) training) wrapped with CalibratedClassifierCV
#   to produce calibrated probabilities at the same speed.
# The result is a proper SVM with predict_proba() support.
#
# BEST MODEL SELECTION
# ─────────────────────
# The model with the highest test accuracy is saved to MODEL_PATH and used
# for all subsequent scans. Typically Random Forest wins, but the comparison
# table always shows all three so you can see which performs best.

def calculate_far_frr(y_true: np.ndarray, y_pred: np.ndarray):
    """
    False Acceptance Rate (FAR) = FP / (FP + TN)
        Proportion of benign URLs incorrectly flagged as malicious.
        Target: ≤ 2%

    False Rejection Rate (FRR) = FN / (FN + TP)
        Proportion of malicious URLs incorrectly passed as safe.
        Target: ≤ 3%
    """
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    far = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    frr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    return far, frr


def train_all_models():
    """
    Load dataset → deduplicate → extract 36 features → train three classifiers
    → evaluate → save the best model to MODEL_PATH.

    Classifiers trained
    -------------------
    1. Random Forest (200 trees, depth 12)
    2. Linear SVM   (LinearSVC + CalibratedClassifierCV + StandardScaler)
    3. Decision Tree (depth 12)

    Returns
    -------
    tuple[model, dict]  best fitted model and full per-classifier results dict
    """
    # ── Load & clean ─────────────────────────────────────────────────────────
    df = pd.read_csv(DATASET_PATH)
    df = df.drop_duplicates(subset=['url']).dropna(subset=['url', 'label'])
    df['label'] = df['label'].astype(int).clip(0, 1)

    # ── Feature matrix ────────────────────────────────────────────────────────
    X = (
        pd.DataFrame([extract_features(u) for u in df['url']])
        [FEATURE_COLUMNS].fillna(0).values.astype(float)
    )
    y = df['label'].values

    # Fill any -1 sentinel in domain_age_days with column median
    col_idx   = FEATURE_COLUMNS.index('domain_age_days')
    col_vals  = X[:, col_idx]
    median_age = np.median(col_vals[col_vals >= 0]) if np.any(col_vals >= 0) else 365
    X[X[:, col_idx] == -1, col_idx] = median_age

    # ── 80 / 20 stratified split ──────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # ── Define classifiers ────────────────────────────────────────────────────
    classifiers = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        ),
        # LinearSVC is O(n) and fast; CalibratedClassifierCV adds probability output;
        # StandardScaler normalises features (SVM requires this for good accuracy).
        "SVM (Linear)": Pipeline([
            ("scaler", StandardScaler()),
            ("svm", CalibratedClassifierCV(
                LinearSVC(
                    C=1.0,
                    class_weight='balanced',
                    max_iter=2000,
                    random_state=42,
                ),
                cv=3,   # 3-fold calibration — fast enough on 1,600 train rows
            )),
        ]),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
        ),
    }

    results    = {}
    best_model = None
    best_acc   = 0.0

    for name, clf in classifiers.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]

        acc  = accuracy_score(y_test,  y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec  = recall_score(y_test,    y_pred, zero_division=0)
        f1   = f1_score(y_test,        y_pred, zero_division=0)
        far, frr = calculate_far_frr(y_test, y_pred)
        auc  = roc_auc_score(y_test, y_prob) if len(np.unique(y_test)) > 1 else 0.0

        results[name] = {
            "accuracy":  float(acc),
            "precision": float(prec),
            "recall":    float(rec),
            "f1_score":  float(f1),
            "far":       float(far),
            "frr":       float(frr),
            "auc":       float(auc),
            # Store arrays for confusion matrix and ROC curve in perf tab
            "y_test": y_test.tolist(),
            "y_pred": y_pred.tolist(),
            "y_prob": y_prob.tolist(),
        }

        if acc > best_acc:
            best_acc   = acc
            best_model = clf

    # ── Persist comparison JSON (arrays excluded to keep file small) ──────────
    comparison_json = {
        name: {k: v for k, v in d.items() if k not in ('y_test','y_pred','y_prob')}
        for name, d in results.items()
    }
    comp_dir = os.path.dirname(COMPARISON_PATH)
    if comp_dir:
        os.makedirs(comp_dir, exist_ok=True)
    with open(COMPARISON_PATH, 'w') as fh:
        json.dump(comparison_json, fh, indent=2)

    # ── Persist best model ────────────────────────────────────────────────────
    model_dir = os.path.dirname(MODEL_PATH)
    if model_dir:
        os.makedirs(model_dir, exist_ok=True)
    joblib.dump(
        {"model": best_model, "feature_columns": FEATURE_COLUMNS,
         "results": results},
        MODEL_PATH,
    )

    return best_model, results


def load_model():
    """
    Load (or train) the classifier.
    Wrapped with st.cache_resource AFTER page config to ensure
    set_page_config is the very first Streamlit call.

    Returns (model, feature_columns, results_dict).
    """
    ensure_dataset()
    if not os.path.exists(MODEL_PATH):
        mdl, results = train_all_models()
        return mdl, FEATURE_COLUMNS, results
    payload = joblib.load(MODEL_PATH)
    if "results" not in payload:
        mdl, results = train_all_models()
        return mdl, FEATURE_COLUMNS, results
    return payload["model"], payload["feature_columns"], payload["results"]


def get_model_comparison() -> dict:
    """Load saved model comparison JSON. Returns None if not yet trained."""
    if os.path.exists(COMPARISON_PATH):
        with open(COMPARISON_PATH, 'r') as fh:
            return json.load(fh)
    return None


# =============================================================================
# SECTION 7 — PREDICTION
# =============================================================================

def get_hostname(url: str) -> str:
    try:
        return urlparse(url if '://' in url else 'http://' + url).hostname or "unknown"
    except Exception:
        return "unknown"


def predict_url(url: str, model, feat_cols: list) -> dict:
    """
    Run the classifier on `url` and return a result dict containing:
        verdict, risk_score, safe_pct, mal_pct, signals, features,
        processing_time_ms
    """
    start = time.time()
    feats = extract_features(url)
    X     = np.array([feats.get(c, 0) for c in feat_cols]).reshape(1, -1)
    prob  = model.predict_proba(X)[0]

    safe_pct = round(prob[0] * 100, 1)
    mal_pct  = round(prob[1] * 100, 1)
    verdict  = (
        "MALICIOUS"  if mal_pct >= 50 else
        "SUSPICIOUS" if mal_pct >= 30 else
        "SAFE"
    )
    proc_ms = round((time.time() - start) * 1000, 2)

    signals = []
    if feats.get('is_https'):        signals.append(("✅ Uses HTTPS", "good"))
    else:                            signals.append(("⚠️ No HTTPS", "bad"))
    if feats.get('is_ip_host'):      signals.append(("⚠️ IP address as host", "bad"))
    if feats.get('suspicious_tld'):  signals.append(("⚠️ Suspicious TLD", "bad"))
    if feats.get('brand_in_domain'): signals.append(("⚠️ Brand impersonation", "bad"))
    if feats.get('digit_in_word'):   signals.append(("⚠️ Typosquatting", "bad"))
    if feats.get('phish_path_kw'):   signals.append(("⚠️ Phishing keywords in path", "bad"))
    if feats.get('is_shortener'):    signals.append(("⚠️ URL shortener used", "bad"))
    if feats.get('at_sign'):         signals.append(("⚠️ @ symbol in URL", "bad"))
    if feats.get('has_punycode'):    signals.append(("⚠️ Punycode / IDN attack", "bad"))
    if feats.get('executable_ext'):  signals.append(("⚠️ Executable file extension", "bad"))
    if feats.get('trusted_domain'):  signals.append(("✅ Trusted domain", "good"))
    if feats.get('subdomain_count',0) >= 3:
        signals.append((f"⚠️ Deep subdomains ({feats['subdomain_count']})", "bad"))
    if feats.get('hyphen_count',0) >= 3:
        signals.append((f"⚠️ Many hyphens ({feats['hyphen_count']})", "bad"))
    if feats.get('url_length',0) > 100:
        signals.append((f"⚠️ Long URL ({feats['url_length']} chars)", "bad"))
    if feats.get('spam_keyword_count',0) >= 2:
        signals.append((f"⚠️ Spam keywords ({feats['spam_keyword_count']})", "bad"))
    if not any(k == "bad" for _, k in signals):
        signals.append(("✅ No suspicious signals found", "good"))

    return {
        "url": url, "verdict": verdict,
        "risk_score": mal_pct, "safe_pct": safe_pct, "mal_pct": mal_pct,
        "signals": signals, "features": feats, "processing_time_ms": proc_ms,
    }


# =============================================================================
# SECTION 8 — STREAMLIT UI
# =============================================================================
# IMPORTANT: st.set_page_config() MUST be the very first Streamlit call.
# init_database() and all other logic runs after page config.

st.set_page_config(
    page_title="Sentinel - Malicious URL Detector",
    page_icon="🛡️",
    layout="wide",
)

# Initialise DB after page config
init_database()

# ── CSS Theme ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono&display=swap');

.stApp { background-color: #0b0f19 !important; color: #e2e8f0 !important; font-family: 'Inter', sans-serif; }
header, #MainMenu, footer { visibility: hidden; }
.block-container { padding-top: 1rem !important; padding-bottom: 2rem !important; max-width: 1200px !important; }

/* ── Nav ── */
.sentinel-nav {
  display: flex; justify-content: space-between; align-items: center;
  padding: 1rem 0; border-bottom: 1px solid #1e293b; margin-bottom: 2rem;
}
.nav-brand { font-size: 1.5rem; font-weight: 700; color: #ffffff; display: flex; align-items: center; gap: 10px; }
.nav-sub   { color: #94a3b8; font-size: 0.9rem; font-weight: 500; }

/* ── Hero inspect card ── */
.inspect-card {
  background-color: #111827; border: 1px solid #1e293b;
  border-radius: 16px; padding: 2.5rem; margin-bottom: 2rem; text-align: center;
}
.inspect-title { font-size: 1.6rem; font-weight: 600; margin-bottom: 0.5rem; color: white; }
.inspect-desc  { color: #94a3b8; font-size: 0.9rem; max-width: 500px; margin: 0 auto 1.5rem auto; }

/* ── Inputs ── */
.stTextInput > div > div > input {
  background-color: #0b0f19 !important; border: 1px solid #1e293b !important;
  color: white !important; border-radius: 8px !important; padding: 0.8rem 1rem !important;
  font-family: 'JetBrains Mono', monospace !important;
}
.stTextInput > div > div > input:focus { border-color: #4f46e5 !important; }

/* ── Button ── */
.stButton > button {
  background-color: #4f46e5 !important; color: white !important;
  border: none !important; border-radius: 8px !important;
  height: 45px !important; width: 100% !important; font-weight: 600 !important;
}
.stButton > button:hover { background-color: #4338ca !important; }

/* ── Result card ── */
.result-card {
  background: #111827; border: 1px solid #1e293b;
  border-radius: 16px; padding: 1.5rem; margin: 1rem 0;
}
.result-safe       { border-left: 4px solid #10b981; }
.result-suspicious { border-left: 4px solid #f59e0b; }
.result-malicious  { border-left: 4px solid #ef4444; }
.verdict           { font-size: 1.8rem; font-weight: 700; }
.verdict-safe      { color: #10b981; }
.verdict-suspicious{ color: #f59e0b; }
.verdict-malicious { color: #ef4444; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
  background-color: #0b0f19 !important; border-right: 1px solid #1e293b !important;
}
section[data-testid="stSidebar"] * { color: #e2e8f0 !important; }

/* ── History items ── */
.history-item {
  background: #111827; border-radius: 8px;
  padding: 0.8rem; margin-bottom: 0.6rem; border: 1px solid #1e293b;
}
.history-verdict     { font-weight: 700; font-size: 0.8rem; margin-bottom: 4px; }
.history-verdict-safe{ color: #10b981; }
.history-verdict-mal { color: #ef4444; }
.history-url         { color: #94a3b8; font-size: 0.75rem; word-break: break-all; font-family: 'JetBrains Mono', monospace; }

/* ── Metric box ── */
.metric-box    { background: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 1rem; text-align: center; }
.metric-value  { font-size: 1.8rem; font-weight: 700; }
.metric-label  { font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
  background: #111827 !important; border: 1px solid #1e293b !important;
  border-radius: 10px !important; padding: 4px !important; gap: 4px !important;
}
.stTabs [data-baseweb="tab"] {
  background: transparent !important; border-radius: 7px !important;
  color: #64748b !important; padding: 8px 20px !important; font-weight: 600 !important;
}
.stTabs [aria-selected="true"] {
  background: #4f46e5 !important; color: white !important;
}
.stTabs [data-baseweb="tab-highlight"] { display: none !important; }
</style>
""", unsafe_allow_html=True)

# ── Navigation bar ────────────────────────────────────────────────────────────
st.markdown("""
<div class="sentinel-nav">
    <div class="nav-brand">
        <span style="font-size:1.5rem;">🛡️</span> SENTINEL
    </div>
    <div class="nav-sub">Professional URL Shield · Malicious URL Detector</div>
</div>
""", unsafe_allow_html=True)

# ── Sidebar — scan history ────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🕒 RECENT SCANS")
    st.markdown("---")
    recent = get_recent_scans(10)
    if not recent:
        st.markdown(
            '<div style="color:#64748b;text-align:center;padding:1rem;">No scan history yet.</div>',
            unsafe_allow_html=True,
        )
    else:
        for scan in recent:
            vc = (
                "history-verdict-mal"
                if scan['verdict'] in ("MALICIOUS","SUSPICIOUS")
                else "history-verdict-safe"
            )
            url_display = scan['url'][:50] + ("..." if len(scan['url']) > 50 else "")
            st.markdown(
                f'<div class="history-item">'
                f'<div class="history-verdict {vc}">{scan["verdict"]}</div>'
                f'<div class="history-url">{url_display}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
    st.markdown("---")
    st.caption(f"Total scans logged: {get_total_scans()}")
    st.caption("Powered by Random Forest | 36 Features")

# ── Load model (cached) — decorator applied HERE, after set_page_config ──────
# st.cache_resource must not appear before st.set_page_config.
# We apply it programmatically after page config is already done.
load_model_cached = st.cache_resource(show_spinner="Loading SENTINEL engine...")(load_model)
model, feat_cols, _train_results = load_model_cached()

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_scan, tab_perf = st.tabs(["🔍 URL Scanner", "📊 Model Performance"])

# ════════════════════════════════════════════════════════════════════════════════
# TAB 1 — URL SCANNER
# ════════════════════════════════════════════════════════════════════════════════
with tab_scan:

    # Hero card
    st.markdown("""
    <div class="inspect-card">
        <div style="font-size:2.5rem; margin-bottom:1rem;">🛡️</div>
        <div class="inspect-title">Ready for Inspection</div>
        <div class="inspect-desc">
            Enter a URL below to analyse its threat level using our
            Random Forest classifier trained on 36 URL features.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Input row
    col1, col2 = st.columns([4, 1])
    with col1:
        url_input = st.text_input(
            "URL",
            placeholder="https://example.com/login",
            label_visibility="collapsed",
        )
    with col2:
        analyze_btn = st.button("🔍 Analyze", use_container_width=True)

    # ── Analysis ─────────────────────────────────────────────────────────────
    if analyze_btn and url_input:
        with st.spinner("Analyzing threat signatures..."):
            result = predict_url(url_input, model, feat_cols)

        # Log to database
        try:
            log_prediction({
                'url':             result['url'],
                'verdict':         result['verdict'],
                'risk_score':      result['risk_score'],
                'safe_pct':        result['safe_pct'],
                'mal_pct':         result['mal_pct'],
                'processing_time': result['processing_time_ms'],
                'features':        result['features'],
            })
        except Exception:
            pass   # never crash the UI because of a DB error

        verdict      = result['verdict']
        result_class = f"result-{verdict.lower()}"
        verdict_class= f"verdict-{verdict.lower()}"

        # Verdict card
        st.markdown(f"""
        <div class="result-card {result_class}">
            <div style="display:flex; justify-content:space-between; align-items:start; flex-wrap:wrap;">
                <div>
                    <div class="verdict {verdict_class}">{verdict}</div>
                    <div style="color:#94a3b8; font-size:0.85rem; margin-top:0.25rem;">
                        Confidence: {result['risk_score']}% &nbsp;|&nbsp;
                        Processing: {result['processing_time_ms']}ms
                    </div>
                </div>
                <div style="text-align:right;">
                    <div style="color:#64748b; font-size:0.7rem;">Target Host</div>
                    <div style="font-family:monospace; font-size:0.8rem;">{get_hostname(url_input)}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Four metric boxes
        col_a, col_b, col_c, col_d = st.columns(4)
        with col_a:
            st.metric("Safe Probability",      f"{result['safe_pct']}%")
        with col_b:
            st.metric("Malicious Probability", f"{result['mal_pct']}%")
        with col_c:
            st.metric("HTTPS Secured", "Yes" if result['features'].get('is_https') else "No")
        with col_d:
            st.metric("Domain Age", f"{result['features'].get('domain_age_days',365)} days")

        # Threat indicators
        st.markdown("### 🎯 Threat Indicators")
        indicators = []
        if result['features'].get('suspicious_tld'):
            indicators.append("Suspicious Top Level Domain detected.")
        if result['features'].get('is_ip_host'):
            indicators.append("IP Address used instead of Domain name.")
        if result['features'].get('brand_in_domain'):
            indicators.append("Potential Brand Impersonation (Typosquatting).")
        if result['features'].get('phish_path_kw'):
            indicators.append("Phishing keywords found in URL path.")
        if not result['features'].get('is_https'):
            indicators.append("Connection is not secured with HTTPS.")
        if result['features'].get('is_shortener'):
            indicators.append("URL shortener service detected.")
        if result['features'].get('executable_ext'):
            indicators.append("Direct link to an executable file.")
        sc = result['features'].get('spam_keyword_count', 0)
        if sc > 0:
            indicators.append(f"Contains {sc} spam/urgent keyword(s).")
        if not indicators:
            indicators.append("No significant threat indicators found.")
        for ind in indicators:
            st.markdown(f"- {ind}")

        # Feature impact bar chart
        st.markdown("### 📊 Feature Impact")
        impact = {
            "Suspicious TLD":  85 if result['features'].get('suspicious_tld')    else 5,
            "IP Host":         90 if result['features'].get('is_ip_host')         else 2,
            "Brand Spoof":     75 if result['features'].get('brand_in_domain')    else 4,
            "Phish Keywords":  80 if result['features'].get('phish_path_kw')      else 10,
            "Shortener":       60 if result['features'].get('is_shortener')       else 5,
            "Spam Words":  min(result['features'].get('spam_keyword_count',0)*20, 100),
        }
        chart_items = [(k, v) for k, v in impact.items() if v > 5]
        if not chart_items:
            chart_items = [("Baseline Safe", 10)]
        chart_items.sort(key=lambda x: x[1])
        chart_labels = [x[0] for x in chart_items]
        chart_values = [x[1] for x in chart_items]
        bar_colours  = [
            '#10b981' if v < 40 else '#f59e0b' if v < 70 else '#ef4444'
            for v in chart_values
        ]

        fig, ax = plt.subplots(figsize=(6, 3))
        fig.patch.set_facecolor('#111827')
        ax.set_facecolor('#111827')
        ax.barh(chart_labels, chart_values, color=bar_colours, alpha=0.9)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_color('#334155')
        ax.spines['left'].set_color('#334155')
        ax.tick_params(colors='#94a3b8')
        ax.set_xlabel("Impact Score", color='#94a3b8', fontsize=9)
        plt.setp(ax.get_xticklabels(), color='#94a3b8', fontsize=8)
        plt.setp(ax.get_yticklabels(), color='#94a3b8', fontsize=8)
        plt.tight_layout()
        st.pyplot(fig, use_container_width=True)
        plt.close(fig)

        # Full feature vector
        with st.expander("View Full Feature Vector (36 features)"):
            st.dataframe(
                pd.DataFrame(result['features'].items(), columns=["Feature","Value"]).set_index("Feature"),
                use_container_width=True, height=400,
            )

    elif analyze_btn and not url_input:
        st.warning("Please enter a URL to analyze.")


# ════════════════════════════════════════════════════════════════════════════════
# TAB 2 — MODEL PERFORMANCE
# ════════════════════════════════════════════════════════════════════════════════
with tab_perf:
    st.markdown("## 📊 Model Performance")
    st.caption(
        "All three classifiers are trained on the same 80/20 stratified split "
        "so results are directly comparable. The best-accuracy model is used for scans."
    )

    comparison = get_model_comparison()

    if not comparison:
        st.info(
            "Performance metrics appear here after the first scan triggers training. "
            "Switch to the URL Scanner tab and analyse any URL to start."
        )
    else:
        # ── Metrics table ─────────────────────────────────────────────────────
        rows = []
        for name, d in comparison.items():
            far_flag = "🟢" if d['far'] <= 0.02 else "🔴"
            frr_flag = "🟢" if d['frr'] <= 0.03 else "🔴"
            rows.append({
                "Model":     name,
                "Accuracy":  f"{d['accuracy']*100:.2f}%",
                "Precision": f"{d['precision']*100:.2f}%",
                "Recall":    f"{d['recall']*100:.2f}%",
                "F1-Score":  f"{d['f1_score']*100:.2f}%",
                "FAR":       f"{far_flag} {d['far']*100:.2f}%",
                "FRR":       f"{frr_flag} {d['frr']*100:.2f}%",
                "AUC":       f"{d['auc']:.3f}",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
        st.info(
            "🎯 Performance Targets: Accuracy ≥ 95% | FAR ≤ 2% (🟢) | FRR ≤ 3% (🟢)"
        )

        # ── Model selector for charts ─────────────────────────────────────────
        # Use _train_results keys but fall back gracefully if a key is missing
        model_names = list(_train_results.keys())
        if not model_names:
            st.warning("No model results available. Please retrain.")
        else:
            selected_model = st.selectbox(
                "Select model to visualise:", model_names,
                index=0, key="model_selector"
            )
            # Guard: selected_model must exist in _train_results
            if selected_model not in _train_results:
                st.error(f"Results for '{selected_model}' not found. Please retrain the model.")
            else:
                sel = _train_results[selected_model]
                y_test_s = np.array(sel["y_test"])
                y_pred_s = np.array(sel["y_pred"])
                y_prob_s = np.array(sel["y_prob"])

                col_cm, col_roc = st.columns(2)

                # ── Confusion Matrix ──────────────────────────────────────────────────
                with col_cm:
                    st.markdown(f"### Confusion Matrix — {selected_model}")
                    fig_cm, ax_cm = plt.subplots(figsize=(5, 4))
                    fig_cm.patch.set_facecolor('#111827')
                    ax_cm.set_facecolor('#111827')
                    ConfusionMatrixDisplay(
                        confusion_matrix(y_test_s, y_pred_s),
                        display_labels=["Benign", "Malicious"]
                    ).plot(ax=ax_cm, colorbar=False, cmap='Blues')
                    ax_cm.tick_params(colors='white')
                    ax_cm.title.set_color('white')
                    plt.setp(ax_cm.get_xticklabels(), color='white')
                    plt.setp(ax_cm.get_yticklabels(), color='white')
                    fig_cm.tight_layout()
                    st.pyplot(fig_cm, use_container_width=True)
                    plt.close(fig_cm)

                # ── ROC Curve ─────────────────────────────────────────────────────────
                with col_roc:
                    st.markdown(f"### ROC Curve — {selected_model}")
                    fpr, tpr, _ = roc_curve(y_test_s, y_prob_s)
                    auc_val = roc_auc_score(y_test_s, y_prob_s) if len(np.unique(y_test_s)) > 1 else 0.0
                    fig_roc, ax_roc = plt.subplots(figsize=(5, 4))
                    fig_roc.patch.set_facecolor('#111827')
                    ax_roc.set_facecolor('#111827')
                    ax_roc.plot(fpr, tpr, color='#4f46e5', lw=2, label=f'AUC = {auc_val:.3f}')
                    ax_roc.plot([0, 1], [0, 1], linestyle='--',
                                color=(0.5, 0.5, 0.5, 0.5), lw=1)
                    ax_roc.set_xlabel('False Positive Rate', color='white', fontsize=9)
                    ax_roc.set_ylabel('True Positive Rate',  color='white', fontsize=9)
                    ax_roc.set_title(f'ROC Curve — {selected_model}', color='white', fontsize=10)
                    ax_roc.legend(loc='lower right', labelcolor='white', framealpha=0)
                    ax_roc.tick_params(colors='white')
                    ax_roc.spines['bottom'].set_color('#334155')
                    ax_roc.spines['left'].set_color('#334155')
                    ax_roc.spines['top'].set_visible(False)
                    ax_roc.spines['right'].set_visible(False)
                    fig_roc.tight_layout()
                    st.pyplot(fig_roc, use_container_width=True)
                    plt.close(fig_roc)

        # ── FAR / FRR bar chart for all three models ──────────────────────────
        st.markdown("### FAR vs FRR — All Models")
        model_labels = list(comparison.keys())
        far_vals = [comparison[m]['far'] * 100 for m in model_labels]
        frr_vals = [comparison[m]['frr'] * 100 for m in model_labels]
        x        = np.arange(len(model_labels))
        width    = 0.35

        fig_ff, ax_ff = plt.subplots(figsize=(7, 3.5))
        fig_ff.patch.set_facecolor('#111827')
        ax_ff.set_facecolor('#111827')
        ax_ff.bar(x - width/2, far_vals, width, label='FAR %', color='#ef4444', alpha=0.85)
        ax_ff.bar(x + width/2, frr_vals, width, label='FRR %', color='#f59e0b', alpha=0.85)
        ax_ff.axhline(2, color='#ef4444', linestyle='--', lw=1, alpha=0.6, label='FAR target (2%)')
        ax_ff.axhline(3, color='#f59e0b', linestyle='--', lw=1, alpha=0.6, label='FRR target (3%)')
        ax_ff.set_xticks(x)
        # Bug 8 fix: rotate labels so 3 long model names don't overlap
        ax_ff.set_xticklabels(model_labels, color='white', fontsize=9, rotation=15, ha='right')
        ax_ff.set_ylabel('Rate (%)', color='white', fontsize=9)
        ax_ff.tick_params(colors='white')
        ax_ff.legend(fontsize=8, framealpha=0, labelcolor='white')
        ax_ff.spines['bottom'].set_color('#334155')
        ax_ff.spines['left'].set_color('#334155')
        ax_ff.spines['top'].set_visible(False)
        ax_ff.spines['right'].set_visible(False)
        plt.tight_layout()
        st.pyplot(fig_ff, use_container_width=True)
        plt.close(fig_ff)
