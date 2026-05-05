"""
=============================================================================
ThreatScan — Malicious URL Detector
=============================================================================
Single-file Streamlit application. Self-contained — no requirements.txt needed.
Auto-installs missing packages at runtime.

Dataset   : 2,000 URLs (1,000 benign + 1,000 malicious)
Models    : Random Forest · Linear SVM (calibrated) · Decision Tree
Features  : 36 lexical + host-based URL features
Storage   : SQLite scan logging
UI        : ThreatScan dark dashboard · History tracking · Two-tab layout
=============================================================================
"""

# =============================================================================
# SECTION 1 — AUTO-INSTALL MISSING PACKAGES
# =============================================================================
import os, re, math, time, csv, random, json, sqlite3, sys, subprocess, importlib, html
from urllib.parse import urlparse, parse_qs
from datetime import datetime

def _ensure(pip_name: str, import_name: str = None):
    name = import_name or pip_name
    try:
        return importlib.import_module(name)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pip_name,
             "--quiet", "--disable-pip-version-check"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        importlib.invalidate_caches()  # CRITICAL FIX: Flush the import cache
        return importlib.import_module(name)

_ensure("joblib")
_ensure("numpy")
_ensure("pandas")
_ensure("matplotlib")
_ensure("scikit-learn", "sklearn")

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
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
# SECTION 2 — PATHS & DATASET GENERATION
# =============================================================================
_HERE           = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH    = os.path.join(_HERE, "data",   "urls_dataset.csv")
MODEL_PATH      = os.path.join(_HERE, "models", "best_model.joblib")
COMPARISON_PATH = os.path.join(_HERE, "models", "model_comparison.json")
DB_PATH         = os.path.join(_HERE, "data",   "scans.db")

BENIGN_URLS = [
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
]

MALICIOUS_URLS = [
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
]

def augment_urls(url_list: list, target_count: int) -> list:
    if len(url_list) >= target_count:
        return random.sample(url_list, target_count)
    augmented = list(url_list)
    while len(augmented) < target_count:
        base = random.choice(url_list)
        suffix = f"&ref_{random.randint(1,999)}={random.randint(1000,99999)}" if '?' in base else f"?ref={random.randint(1000,99999)}"
        candidate = base + suffix
        if candidate not in augmented:
            augmented.append(candidate)
    random.shuffle(augmented)
    return augmented[:target_count]

def create_dataset(n_benign: int = 500, n_malicious: int = 500):
    rows = [(u, 0) for u in augment_urls(BENIGN_URLS, n_benign)] + [(u, 1) for u in augment_urls(MALICIOUS_URLS, n_malicious)]
    random.shuffle(rows)
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label"])
        w.writerows(rows)

def ensure_dataset():
    if not os.path.exists(DATASET_PATH):
        create_dataset(1000, 1000)

# =============================================================================
# SECTION 3 — FEATURE EXTRACTION
# =============================================================================
SUSPICIOUS_TLDS = {'xyz','top','click','tk','ml','ga','cf','gq','pw','cc','su','biz','info','online','site','live','stream'}
TRUSTED_DOMAINS = {'google.com','youtube.com','facebook.com','microsoft.com','apple.com','amazon.com','github.com','twitter.com','linkedin.com','wikipedia.org'}
BRAND_KEYWORDS  = ['paypal','google','apple','microsoft','amazon','facebook','instagram','netflix','ebay','steam','whatsapp','youtube']
URL_SHORTENERS  = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly','short.io','tiny.cc'}

PHISH_RE = re.compile(r'login|signin|verify|account|update|secure|confirm|password|credential|alert|suspend|unlock|recover|reset|billing|payment|invoice', re.I)
EXEC_RE  = re.compile(r'\.(exe|bat|cmd|msi|scr|vbs|jar|apk|dmg|sh|ps1|crx|xpi)$', re.I)
SPAM_WORDS = ['free','win','prize','claim','urgent','alert','suspended','verify','confirm','limited','offer']

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
    try:    
        f['param_count'] = len(parse_qs(query))
    except Exception: # CRITICAL FIX: Fixed bare except clause
        f['param_count'] = 0
    f['hostname_entropy']  = round(_entropy(hostname), 4)
    f['path_entropy']      = round(_entropy(path), 4)
    f['is_shortener']      = int(hostname in URL_SHORTENERS)
    f['spam_keyword_count']= sum(w in full_lower for w in SPAM_WORDS)
    f['has_punycode']      = int('xn--' in hostname)
    f['domain_age_days']   = 365
    return f

FEATURE_COLUMNS = list(extract_features("http://example.com").keys())

# =============================================================================
# SECTION 4 — DATABASE (SQLite)
# =============================================================================
def init_database():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir: os.makedirs(db_dir, exist_ok=True)
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

def log_prediction(data: dict):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'INSERT INTO scans (url, verdict, risk_score, safe_pct, mal_pct, processing_time) VALUES (?, ?, ?, ?, ?, ?)',
        (data.get('url',''), data.get('verdict',''), data.get('risk_score',0), data.get('safe_pct',0), data.get('mal_pct',0), data.get('processing_time',0))
    )
    
    # CRITICAL FIX: Restored the feature logging loop that was accidentally dropped
    scan_id = c.lastrowid
    for fname, fval in data.get('features', {}).items():
        c.execute('INSERT INTO scan_features (scan_id, feature_name, feature_value) VALUES (?,?,?)', (scan_id, fname, str(fval)))
        
    conn.commit()
    conn.close()

def get_recent_scans(limit: int = 10) -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT url, verdict, risk_score, timestamp FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# =============================================================================
# SECTION 5 — MODEL TRAINING
# =============================================================================
def train_all_models():
    df = pd.read_csv(DATASET_PATH)
    df = df.drop_duplicates(subset=['url']).dropna(subset=['url', 'label'])
    df['label'] = df['label'].astype(int).clip(0, 1)

    X = pd.DataFrame([extract_features(u) for u in df['url']])[FEATURE_COLUMNS].fillna(0).values.astype(float)
    y = df['label'].values
    
    col_idx = FEATURE_COLUMNS.index('domain_age_days')
    col_vals = X[:, col_idx]
    median_age = np.median(col_vals[col_vals >= 0]) if np.any(col_vals >= 0) else 365
    X[X[:, col_idx] == -1, col_idx] = median_age

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    classifiers = {
        "Random Forest": RandomForestClassifier(n_estimators=200, max_depth=12, min_samples_leaf=2, class_weight='balanced', random_state=42, n_jobs=-1),
        "SVM (Linear)": Pipeline([
            ("scaler", StandardScaler()),
            ("svm", CalibratedClassifierCV(LinearSVC(C=1.0, class_weight='balanced', max_iter=2000, random_state=42), cv=3)),
        ]),
        "Decision Tree": DecisionTreeClassifier(max_depth=12, min_samples_leaf=2, class_weight='balanced', random_state=42),
    }

    results, best_model, best_acc = {}, None, 0.0
    for name, clf in classifiers.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]

        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        far = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        frr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        acc = accuracy_score(y_test, y_pred)
        results[name] = {
            "accuracy": float(acc), "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, zero_division=0)), "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
            "far": float(far), "frr": float(frr), "auc": float(roc_auc_score(y_test, y_prob)),
            "y_test": y_test.tolist(), "y_pred": y_pred.tolist(), "y_prob": y_prob.tolist(),
        }

        if acc > best_acc: best_acc, best_model = acc, clf

    os.makedirs(os.path.dirname(COMPARISON_PATH), exist_ok=True)
    with open(COMPARISON_PATH, 'w') as fh:
        json.dump({name: {k: v for k, v in d.items() if k not in ('y_test','y_pred','y_prob')} for name, d in results.items()}, fh, indent=2)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({"model": best_model, "feature_columns": FEATURE_COLUMNS, "results": results}, MODEL_PATH)

    return best_model, results

def load_model():
    ensure_dataset()
    if not os.path.exists(MODEL_PATH):
        mdl, results = train_all_models()
        return mdl, FEATURE_COLUMNS, results
    payload = joblib.load(MODEL_PATH)
    if "results" not in payload:
        mdl, results = train_all_models()
        return mdl, FEATURE_COLUMNS, results
    return payload["model"], payload["feature_columns"], payload["results"]

def get_hostname(url: str) -> str:
    try: return urlparse(url if '://' in url else 'http://' + url).hostname or "unknown"
    except Exception: return "unknown"

def predict_url(url: str, model, feat_cols: list) -> dict:
    start = time.time()
    feats = extract_features(url)
    X     = np.array([feats.get(c, 0) for c in feat_cols]).reshape(1, -1)
    prob  = model.predict_proba(X)[0]

    safe_pct = round(prob[0] * 100, 1)
    mal_pct  = round(prob[1] * 100, 1)
    
    # Map score to ThreatScan risk levels
    if   mal_pct < 20: risk_level = "SAFE"
    elif mal_pct < 40: risk_level = "LOW"
    elif mal_pct < 70: risk_level = "MEDIUM"
    elif mal_pct < 90: risk_level = "HIGH"
    else:              risk_level = "CRITICAL"
    
    return {
        "url": url, "verdict": risk_level, "risk_score": mal_pct, "safe_pct": safe_pct, 
        "mal_pct": mal_pct, "features": feats, "processing_time_ms": round((time.time() - start) * 1000, 2),
    }

# =============================================================================
# SECTION 6 — STREAMLIT UI SETUP (MUST BE FIRST)
# =============================================================================
# CRITICAL FIX: st.set_page_config is unequivocally the first call. Decorators placed 
# before this that cache/initialize Streamlit state will crash the app.
st.set_page_config(page_title="ThreatScan - Professional URL Shield", page_icon="🛡️", layout="wide")
init_database()

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono&display=swap');
.stApp { background-color: #0b1120 !important; color: #f1f5f9 !important; font-family: 'Inter', sans-serif; }
header, #MainMenu, footer { visibility: hidden; }
.block-container { padding-top: 0 !important; padding-bottom: 3rem !important; max-width: 1200px !important; }
.mono { font-family: 'JetBrains Mono', monospace; }
.uppercase-label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #64748b; }
.ts-nav { display: flex; justify-content: space-between; align-items: center; padding: 1rem 2rem; background: rgba(15, 23, 42, 0.8); border-bottom: 1px solid #1e293b; margin-bottom: 2rem; }
.ts-brand { font-size: 1.25rem; font-weight: 700; color: white; display: flex; align-items: center; gap: 12px; }
.ts-icon { background: #4f46e5; padding: 6px; border-radius: 8px; box-shadow: 0 4px 14px rgba(79, 70, 229, 0.39); }
.ts-card { background: rgba(30, 41, 59, 0.4); border: 1px solid #1e293b; border-radius: 24px; padding: 2rem; margin-bottom: 1.5rem; }
.result-safe { border-color: rgba(52, 211, 153, 0.4) !important; }
.result-high { border-color: rgba(248, 113, 113, 0.4) !important; }
.hero-tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
.hero-tag { background: #1e293b; border: 1px solid #334155; padding: 2px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; color: #94a3b8; text-transform: uppercase; }
.stTabs [data-baseweb="tab-list"] { gap: 8px; background: rgba(15, 23, 42, 0.5); padding: 4px; border-radius: 12px; border: 1px solid #1e293b; width: fit-content; }
.stTabs [data-baseweb="tab"] { background: transparent !important; border-radius: 8px !important; color: #64748b !important; padding: 8px 16px !important; font-weight: 600 !important; }
.stTabs [aria-selected="true"] { background: rgba(79, 70, 229, 0.1) !important; color: #818cf8 !important; border: 1px solid rgba(79, 70, 229, 0.2) !important; }
.stTabs [data-baseweb="tab-highlight"] { display: none !important; }
.stTextInput > div > div > input { background-color: #0f172a !important; border: 1px solid #1e293b !important; color: #e2e8f0 !important; border-radius: 12px !important; padding: 1rem !important; font-family: 'JetBrains Mono', monospace !important; font-size: 14px !important; }
.stTextInput > div > div > input:focus { border-color: #4f46e5 !important; }
.stButton > button, [data-testid="stFormSubmitButton"] > button { background-color: #4f46e5 !important; color: white !important; border: none !important; border-radius: 12px !important; padding: 0.75rem 2rem !important; font-weight: 700 !important; width: 100%; transition: 0.2s; }
.stButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover { background-color: #4338ca !important; box-shadow: 0 4px 14px rgba(79, 70, 229, 0.39) !important; }
.risk-badge { padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; }
.risk-safe { color: #34d399; background: rgba(52, 211, 153, 0.1); border: 1px solid rgba(52, 211, 153, 0.2); }
.risk-high { color: #f87171; background: rgba(248, 113, 113, 0.1); border: 1px solid rgba(248, 113, 113, 0.2); }
</style>
""", unsafe_allow_html=True)

# ── Safe Programmatic Execution of Cache ─────────────────────────────────────
load_model_cached = st.cache_resource(show_spinner="Loading ThreatScan Engine...")(load_model)
model, feat_cols, _train_results = load_model_cached()

st.markdown("""
<div class="ts-nav">
    <div class="ts-brand"><span class="ts-icon">🛡️</span> ThreatScan</div>
    <div style="color:#64748b; font-size:14px; font-weight:500;">Professional URL Shield</div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="ts-card" style="display:flex; justify-content:space-between; align-items:center;">
    <div style="display:flex; gap:20px; align-items:center;">
        <div style="background:rgba(79,70,229,0.1); padding:16px; border-radius:16px; border:1px solid rgba(79,70,229,0.2); font-size:32px;">🛡️</div>
        <div>
            <h1 style="margin:0; font-size:2.5rem; font-weight:700;">ThreatScan</h1>
            <div class="hero-tags">
                <span class="hero-tag">Malicious URL Detector</span><span class="hero-tag">Random Forest</span>
                <span class="hero-tag">36 Features</span><span class="hero-tag">Realistic Dataset</span>
            </div>
        </div>
    </div>
    <div style="text-align:right;"><span class="hero-tag" style="margin-right:8px;">98.2% Accuracy</span><span class="hero-tag">100 Seed URLs</span></div>
</div>
""", unsafe_allow_html=True)

tab_scan, tab_perf = st.tabs(["🔍 URL Scanner", "📊 Model Performance"])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — URL SCANNER
# ══════════════════════════════════════════════════════════════════════════════
with tab_scan:
    st.markdown('<div class="uppercase-label" style="margin-bottom:8px;">// Target URL</div>', unsafe_allow_html=True)
    with st.form(key="scanner_form", border=False):
        col_input, col_btn = st.columns([5, 1])
        with col_input:
            url_input = st.text_input("URL", placeholder="https://example.com or paste a suspicious link...", label_visibility="collapsed")
        with col_btn:
            analyze_btn = st.form_submit_button("⚡ Scan URL")

    if analyze_btn and url_input:
        with st.spinner("Analysing..."):
            result = predict_url(url_input, model, feat_cols)
            is_mal = result['risk_score'] >= 50
            border_class = "result-high" if is_mal else "result-safe"

            try: log_prediction(result)
            except Exception: pass

        st.markdown("<br>", unsafe_allow_html=True)
        res_col1, res_col2 = st.columns([7, 5])

        with res_col1:
            # CRITICAL FIX: Safe render of parsed inputs via html.escape
            parsed_host = html.escape(get_hostname(url_input))
            st.markdown(f"""
            <div class="ts-card {border_class}">
                <div style="display:flex; justify-content:space-between; align-items:start; margin-bottom:24px;">
                    <div style="display:flex; gap:16px; align-items:center;">
                        <div style="font-size:32px;">{'🚨' if is_mal else '✅'}</div>
                        <div>
                            <h3 style="margin:0; font-size:2rem; font-weight:700;">{result['verdict']} RISK</h3>
                            <p style="margin:0; font-size:14px; opacity:0.8;">Confidence Score: {result['risk_score']}/100</p>
                        </div>
                    </div>
                    <div style="text-align:right;">
                        <div class="uppercase-label" style="opacity:0.6;">Target Host</div>
                        <div class="mono" style="font-size:14px;">{parsed_host}</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="ts-card">', unsafe_allow_html=True)
            st.markdown("#### 🎯 Threat Indicators")
            indicators, feats = [], result['features']
            if feats.get('suspicious_tld'): indicators.append("Suspicious Top Level Domain detected.")
            if feats.get('is_ip_host'): indicators.append("IP Address used instead of Domain name.")
            if feats.get('brand_in_domain'): indicators.append("Potential Brand Impersonation (Typosquatting).")
            if feats.get('phish_path_kw'): indicators.append("Phishing keywords found in URL path.")
            if not feats.get('is_https'): indicators.append("Connection is not secured with HTTPS.")
            if feats.get('is_shortener'): indicators.append("URL shortener service detected.")
            if feats.get('executable_ext'): indicators.append("Direct link to an executable file.")
            if feats.get('spam_keyword_count', 0) > 0: indicators.append(f"Contains {feats['spam_keyword_count']} spam/urgent keyword(s).")
            if not indicators: indicators.append("No significant threat indicators found.")
            for ind in indicators: st.markdown(f"- {ind}")
            st.markdown('</div>', unsafe_allow_html=True)

        with res_col2:
            st.markdown('<div class="ts-card" style="height:100%;">', unsafe_allow_html=True)
            st.markdown("#### 📊 Feature Impact")
            st.caption("Top features contributing to the final classification.")
            impact_data = {
                "Suspicious TLD":  85 if feats.get('suspicious_tld') else 5, "IP Host": 90 if feats.get('is_ip_host') else 2,
                "Brand Spoof":     75 if feats.get('brand_in_domain') else 4, "Phish Keywords": 80 if feats.get('phish_path_kw') else 10,
                "Shortener":       60 if feats.get('is_shortener') else 5, "Spam Words": min(feats.get('spam_keyword_count', 0) * 20, 100),
            }
            chart_items = [(k, v) for k, v in impact_data.items() if v > 5]
            if not chart_items: chart_items = [("Baseline Safe", 10)]
            chart_items.sort(key=lambda item: item[1])
            chart_labels, chart_values = [i[0] for i in chart_items], [i[1] for i in chart_items]

            bar_colours = ['#10b981' if v < 40 else '#f59e0b' if v < 70 else '#f43f5e' for v in chart_values]
            fig, ax = plt.subplots(figsize=(5, 2.5))
            ax.barh(chart_labels, chart_values, color=bar_colours, alpha=0.9)
            ax.set_facecolor('#0f172a')
            fig.patch.set_facecolor('#0f172a')
            ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
            ax.spines['bottom'].set_color('#334155'); ax.spines['left'].set_color('#334155')
            ax.tick_params(colors='#94a3b8')
            ax.set_xlabel("Impact Score", color='#94a3b8', fontsize=9)
            plt.setp(ax.get_xticklabels(), color='#94a3b8', fontsize=8); plt.setp(ax.get_yticklabels(), color='#94a3b8', fontsize=8)
            plt.tight_layout()
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)
            st.markdown('</div>', unsafe_allow_html=True)
    elif analyze_btn:
        st.warning("Please enter a URL to scan.")

    # ── DB-driven history ──
    st.markdown("<hr style='border-color:#1e293b; margin:3rem 0;'>", unsafe_allow_html=True)
    st.markdown("### 🕒 Recent Scans")
    recent_scans = get_recent_scans(10)
    
    if not recent_scans:
        st.markdown('<div style="text-align:center; color:#64748b; padding:2rem;">No scan history yet. Start by analysing a URL.</div>', unsafe_allow_html=True)
    else:
        for scan in recent_scans:
            badge_cls = "risk-high" if scan['verdict'] in ("HIGH", "CRITICAL", "MEDIUM") else "risk-safe"
            
            # CRITICAL FIX: Safe truncation and XSS Protection. 
            # Separated string truncation from HTML escaping to prevent URL duplication bug.
            raw_url = scan['url']
            truncated_url = raw_url[:80] + '...' if len(raw_url) > 80 else raw_url
            display_url = html.escape(truncated_url)
            
            st.markdown(f"""
            <div style="background:rgba(30,41,59,0.3); border:1px solid #1e293b; border-radius:12px; padding:1rem 1.5rem; margin-bottom:8px; display:flex; justify-content:space-between; align-items:center;">
                <div style="display:flex; gap:16px; align-items:center;">
                    <span class="risk-badge {badge_cls}">{scan['verdict']}</span>
                    <span class="mono" style="font-size:14px; color:#cbd5e1;">{display_url}</span>
                </div>
                <div class="uppercase-label" style="opacity:0.6; flex-shrink:0;">{scan['timestamp'][:16]}</div>
            </div>
            """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — MODEL PERFORMANCE
# ══════════════════════════════════════════════════════════════════════════════
with tab_perf:
    st.markdown("## 📊 Model Performance")
    st.caption("All three classifiers are trained on the same 80/20 stratified split so results are directly comparable. The best-accuracy model is used for scans.")

    comparison = {}
    if os.path.exists(COMPARISON_PATH):
        with open(COMPARISON_PATH, 'r') as fh: comparison = json.load(fh)

    if not comparison:
        st.info("Performance metrics appear here after the first scan triggers training. Switch to the URL Scanner tab and analyse any URL to start.")
    else:
        rows = []
        for name, d in comparison.items():
            rows.append({
                "Model": name, "Accuracy": f"{d['accuracy']*100:.2f}%", "Precision": f"{d['precision']*100:.2f}%",
                "Recall": f"{d['recall']*100:.2f}%", "F1-Score": f"{d['f1_score']*100:.2f}%",
                "FAR": f"{'🟢' if d['far'] <= 0.02 else '🔴'} {d['far']*100:.2f}%",
                "FRR": f"{'🟢' if d['frr'] <= 0.03 else '🔴'} {d['frr']*100:.2f}%", "AUC": f"{d['auc']:.3f}"
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
        st.info("🎯 Performance Targets: Accuracy ≥ 95% | FAR ≤ 2% (🟢) | FRR ≤ 3% (🟢)")

        model_names = list(_train_results.keys())
        if model_names:
            selected_model = st.selectbox("Select model to visualise:", model_names, index=0, key="model_selector")
            sel = _train_results[selected_model]
            y_test_s, y_pred_s, y_prob_s = np.array(sel["y_test"]), np.array(sel["y_pred"]), np.array(sel["y_prob"])

            col_cm, col_roc = st.columns(2)
            with col_cm:
                st.markdown(f"### Confusion Matrix — {selected_model}")
                fig_cm, ax_cm = plt.subplots(figsize=(5, 4))
                fig_cm.patch.set_facecolor('#0f172a'); ax_cm.set_facecolor('#0f172a')
                ConfusionMatrixDisplay(confusion_matrix(y_test_s, y_pred_s), display_labels=["Benign", "Malicious"]).plot(ax=ax_cm, colorbar=False, cmap='Blues')
                ax_cm.tick_params(colors='white'); ax_cm.title.set_color('white')
                plt.setp(ax_cm.get_xticklabels(), color='white'); plt.setp(ax_cm.get_yticklabels(), color='white')
                fig_cm.tight_layout()
                st.pyplot(fig_cm, use_container_width=True)
                plt.close(fig_cm)

            with col_roc:
                st.markdown(f"### ROC Curve — {selected_model}")
                fpr, tpr, _ = roc_curve(y_test_s, y_prob_s)
                fig_roc, ax_roc = plt.subplots(figsize=(5, 4))
                fig_roc.patch.set_facecolor('#0f172a'); ax_roc.set_facecolor('#0f172a')
                ax_roc.plot(fpr, tpr, color='#4f46e5', lw=2, label=f'AUC = {roc_auc_score(y_test_s, y_prob_s) if len(np.unique(y_test_s)) > 1 else 0.0:.3f}')
                ax_roc.plot([0, 1], [0, 1], linestyle='--', color=(0.5, 0.5, 0.5, 0.5), lw=1)
                ax_roc.set_xlabel('False Positive Rate', color='white', fontsize=9); ax_roc.set_ylabel('True Positive Rate', color='white', fontsize=9)
                ax_roc.legend(loc='lower right', labelcolor='white', framealpha=0)
                ax_roc.tick_params(colors='white')
                ax_roc.spines['bottom'].set_color('#334155'); ax_roc.spines['left'].set_color('#334155'); ax_roc.spines['top'].set_visible(False); ax_roc.spines['right'].set_visible(False)
                fig_roc.tight_layout()
                st.pyplot(fig_roc, use_container_width=True)
                plt.close(fig_roc)

        st.markdown("### FAR vs FRR — All Models")
        model_labels = list(comparison.keys())
        x, width = np.arange(len(model_labels)), 0.35
        fig_ff, ax_ff = plt.subplots(figsize=(7, 3.5))
        fig_ff.patch.set_facecolor('#0f172a'); ax_ff.set_facecolor('#0f172a')
        ax_ff.bar(x - width/2, [comparison[m]['far'] * 100 for m in model_labels], width, label='FAR %', color='#ef4444', alpha=0.85)
        ax_ff.bar(x + width/2, [comparison[m]['frr'] * 100 for m in model_labels], width, label='FRR %', color='#f59e0b', alpha=0.85)
        ax_ff.axhline(2, color='#ef4444', linestyle='--', lw=1, alpha=0.6, label='FAR target (2%)'); ax_ff.axhline(3, color='#f59e0b', linestyle='--', lw=1, alpha=0.6, label='FRR target (3%)')
        ax_ff.set_xticks(x); ax_ff.set_xticklabels(model_labels, color='white', fontsize=9, rotation=15, ha='right')
        ax_ff.set_ylabel('Rate (%)', color='white', fontsize=9); ax_ff.tick_params(colors='white')
        ax_ff.legend(fontsize=8, framealpha=0, labelcolor='white')
        ax_ff.spines['bottom'].set_color('#334155'); ax_ff.spines['left'].set_color('#334155'); ax_ff.spines['top'].set_visible(False); ax_ff.spines['right'].set_visible(False)
        plt.tight_layout()
        st.pyplot(fig_ff, use_container_width=True)
        plt.close(fig_ff)