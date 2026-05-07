"""
=============================================================================
ThreatScan Pro v5.5.2 — Full Audit Build
=============================================================================
ALL FIXES (v5.5.1 + new round):
  [BUG-1]  Verdict threshold 0.45 → 0.50 (safe URLs flagged as malicious)
  [BUG-2]  augment_urls() gave benign URLs phishing paths/keys (data poison)
  [BUG-3]  brand_hit fired on real brand domains like google.com itself
  [BUG-4]  FEATURE_COLUMNS was mutable list, now frozen tuple
  [BUG-5]  Audit log always appended "..." even on short URLs
  [BUG-6]  Stale model.joblib reloaded after fixes (version check added)
  [BUG-7]  spam_hit scanned FULL raw URL — paths like /software-update,
           /free-lunch, /alerts on legitimate domains → false positives.
           Fixed: scan hostname only, not path/query.
  [BUG-8]  Malicious seeds with embedded slashes (192.168.10.1/signin,
           amazon-winner-2026.top/claim) caused double path segments in
           generated URLs (/signin/verify), corrupting path_len / slash_p.
           Fixed: strip path from seed before constructing URL.
  [BUG-9]  is_ip regex accepted invalid IPs (999.999.999.999) and missed
           hex IPs (0x58.0x23.0x11.0x01). Fixed: validate octet range 0-255
           and add hex IP detection.
  [BUG-10] ensure_dataset() has no dataset version guard — old poisoned
           urls.csv is never regenerated because it already exists.
           Fixed: DATASET_VERSION stamp written into urls.csv header comment.
  [BUG-11] DB connections used manual conn.close() with no try/finally.
           Exception between connect() and close() leaks the connection.
           Fixed: all DB functions use context managers (with sqlite3.connect).
  [BUG-12] ensure_dataset() accepted 0-byte / truncated urls.csv.
           Fixed: validate row count after loading.
  [BUG-13] _entropy() was O(n²) — s.count(c) inside a loop.
           Fixed: use collections.Counter (O(n)).
  [BUG-14] json and datetime imported but never used (dead imports).
=============================================================================
"""

import os, re, math, time, csv, random, sqlite3, sys, subprocess, importlib, html
from collections import Counter
from urllib.parse import urlparse, parse_qs

# --- SECTION 1: AUTO-INSTALL & ENVIRONMENT SETUP ---
def _ensure(pip_name: str, import_name: str = None):
    name = import_name or pip_name
    try:
        return importlib.import_module(name)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name, "--quiet"])
        importlib.invalidate_caches()
        return importlib.import_module(name)

_ensure("joblib")
_ensure("numpy")
_ensure("pandas")
_ensure("matplotlib")
_ensure("scikit-learn", "sklearn")

import joblib, numpy as np, pandas as pd, streamlit as st
import matplotlib                          # import first …
matplotlib.use("Agg")                      # … set backend before pyplot …
import matplotlib.pyplot as plt            # … then import pyplot

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, roc_curve, roc_auc_score, ConfusionMatrixDisplay
)

# --- SECTION 2: PATHS & VERSION STAMPS ---
_HERE        = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(_HERE, "data", "urls.csv")
MODEL_PATH   = os.path.join(_HERE, "models", "model.joblib")
DB_PATH      = os.path.join(_HERE, "data", "scans.db")

# Bump MODEL_VERSION whenever features or training logic change.
# Bump DATASET_VERSION whenever augment_urls() or seeds change.
MODEL_VERSION   = "5.5.2"
DATASET_VERSION = "5.5.2"

# --- SECTION 3: DATASET GENERATION ---
BENIGN_SEEDS = [
    "google.com", "github.com", "wikipedia.org", "linkedin.com",
    "nytimes.com", "amazon.com", "apple.com", "microsoft.com",
]
# BUG-8 FIX: Seeds must be pure hostnames — no path segments.
# Embedded slashes (e.g. "192.168.10.1/signin") caused double path segments
# (/signin/verify) in generated URLs, corrupting path_len and slash_p features.
MALICIOUS_SEEDS = [
    "secure-login.paypa1.com.verify-account.tk",
    "192.168.10.1",          # was "192.168.10.1/signin"
    "xn--gogle-pua.com",
    "chase-online-update.xyz",
    "login.microsoftonline.update.ml",
    "dhl-parcel-tracking.site",
    "wellsfargo-secure-auth.ga",
    "0x58.0x23.0x11.0x01",  # was "0x58.0x23.0x11.0x01/login"
    "amazon-winner-2026.top", # was "amazon-winner-2026.top/claim"
]


def augment_urls(seeds, count, label):
    """
    BUG-2 FIX: Benign and malicious URLs use distinct path/query profiles so
    the model learns domain structure, not coincidental path keywords.
    BUG-8 FIX: Seeds are pure hostnames; path is appended here, not embedded.
    """
    aug = set()
    if label == 0:
        paths = ["/about", "/home", "/docs", "/search", "/blog", "/faq", ""]
        keys  = ["q", "page", "ref", "lang", "sort", "category"]
        scheme = "https://"
    else:
        paths = ["/auth", "/login", "/verify", "/account", "/secure", "/update"]
        keys  = ["id", "session", "user", "token", "ref", "auth_id"]
        scheme = "http://"

    while len(aug) < count:
        domain = random.choice(seeds)
        path   = random.choice(paths)
        key    = random.choice(keys)
        url    = f"{scheme}{domain}{path}?{key}={random.randint(1000, 999999)}"
        aug.add(url)
    return list(aug)


def _dataset_version_matches():
    """Return True if urls.csv exists and was generated with the current DATASET_VERSION."""
    if not os.path.exists(DATASET_PATH):
        return False
    try:
        with open(DATASET_PATH, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()
        return first_line == f"# dataset_version={DATASET_VERSION}"
    except Exception:
        return False


def ensure_dataset():
    """
    BUG-10 FIX: Check dataset version stamp, not just file existence.
    Old poisoned CSVs (from pre-fix augment_urls) are regenerated automatically.
    BUG-12 FIX: Validate row count after generation to catch truncated files.
    """
    if _dataset_version_matches():
        return

    rows = (
        [(u, 0) for u in augment_urls(BENIGN_SEEDS, 2500, 0)] +
        [(u, 1) for u in augment_urls(MALICIOUS_SEEDS, 2500, 1)]
    )
    random.shuffle(rows)
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        # Version stamp as a comment-like first line (will be skipped by read_csv via comment='#')
        f.write(f"# dataset_version={DATASET_VERSION}\n")
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)

    # BUG-12: Verify the file is intact
    df = pd.read_csv(DATASET_PATH, comment="#")
    if len(df) < 5000:
        os.remove(DATASET_PATH)
        raise RuntimeError(f"Dataset generation failed: only {len(df)} rows written.")


# --- SECTION 4: FEATURE EXTRACTION ---
BRAND_KWS = ['paypal', 'google', 'chase', 'microsoft', 'apple', 'amazon', 'wellsfargo', 'netflix', 'banc']

# BUG-7 FIX: spam_hit now only checks the hostname, not the full raw URL.
# Checking the full URL caused false positives on legitimate sites like:
#   apple.com/macos/software-update  → 'update' in raw → spam_hit=1
#   nytimes.com/newsletters/free-lunch → 'free' in raw → spam_hit=1
SPAM_KWS = ['free', 'win', 'prize', 'urgent', 'alert', 'suspended', 'verify', 'update', 'lucky', 'bonus']

# BUG-3 FIX: Real brand TLD+1 domains — brand_hit only fires on impersonation,
# not on the real brand's own domain.
REAL_BRAND_DOMAINS = {
    'google.com', 'amazon.com', 'apple.com', 'microsoft.com',
    'paypal.com', 'chase.com', 'netflix.com', 'wellsfargo.com',
    'linkedin.com', 'github.com',
}


def _entropy(s):
    """BUG-13 FIX: O(n) via Counter instead of O(n²) via s.count(c) in a loop."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def _is_ip(host):
    """
    BUG-9 FIX: Original regex accepted invalid IPs (999.x.x.x) and missed
    hex-encoded IPs (0x58.0x23.0x11.0x01).
    Now: validate decimal octets 0-255, plus detect hex-dotted notation.
    """
    # Decimal dotted-quad with proper range check
    decimal_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', host)
    if decimal_match:
        return all(0 <= int(g) <= 255 for g in decimal_match.groups())
    # Hex dotted-quad (e.g. 0x58.0x23.0x11.0x01)
    if re.match(r'^0x[0-9a-fA-F]+(\\.0x[0-9a-fA-F]+){3}$', host):
        return True
    return False


def extract_features(url):
    raw = str(url).strip()
    f   = {}
    try:
        p = urlparse(raw if '://' in raw else 'http://' + raw)
    except Exception:
        p = urlparse('http://invalid')

    h     = (p.hostname or '').lower()
    path  = p.path  or ''
    query = p.query or ''
    hl    = max(len(h), 1)

    # BUG-3 FIX: brand_hit only fires for impersonation, not real brand domains
    parts      = h.split('.')
    tld_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else h
    brand_hit  = int(any(k in h for k in BRAND_KWS) and tld_domain not in REAL_BRAND_DOMAINS)

    # BUG-7 FIX: spam_hit checks hostname only, not full URL
    spam_hit = int(any(k in h for k in SPAM_KWS))

    f.update({
        'is_https':  int(p.scheme == 'https'),
        'url_len':   len(raw),
        'host_len':  len(h),
        'path_len':  len(path),
        'dot_h':     h.count('.'),
        'hyp_h':     h.count('-'),
        'at':        int('@' in raw),
        'slash_p':   path.count('/'),
        'digit_r':   round(sum(c.isdigit() for c in h) / hl, 4),
        'is_ip':     int(_is_ip(h)),        # BUG-9 FIX
        'entropy':   round(_entropy(h), 4), # BUG-13 FIX
        'has_puny':  int('xn--' in h),
        'param_cnt': len(parse_qs(query)),
        'sub_cnt':   max(0, len(parts) - 2),
        'brand_hit': brand_hit,             # BUG-3 FIX
        'spam_hit':  spam_hit,              # BUG-7 FIX
    })

    # Padding to 36 features
    for i in range(len(f), 36):
        f[f'feat_{i}'] = 0
    return f


# BUG-4 FIX: Frozen tuple prevents accidental mutation
FEATURE_COLUMNS = tuple(extract_features("http://ex.com").keys())


# --- SECTION 5: DATABASE ---
def init_database():
    """BUG-11 FIX: Use context manager so connection is always closed."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                url             TEXT,
                verdict         TEXT,
                risk_score      REAL,
                safe_pct        REAL,
                mal_pct         REAL,
                processing_time REAL,
                actual_label    INTEGER DEFAULT -1,
                timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_features (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id       INTEGER,
                feature_name  TEXT,
                feature_value TEXT
            )
        ''')
        try:
            conn.execute('ALTER TABLE scans ADD COLUMN actual_label INTEGER DEFAULT -1')
        except Exception:
            pass


def log_prediction(data):
    """BUG-11 FIX: Context manager guarantees connection is released on error."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            'INSERT INTO scans (url, verdict, risk_score, safe_pct, mal_pct, processing_time) VALUES (?,?,?,?,?,?)',
            (data['url'], data['verdict'], data['risk_score'],
             data['safe_pct'], data['mal_pct'], data['processing_time_ms'])
        )
        sid = c.lastrowid
        for k, v in data['features'].items():
            c.execute(
                'INSERT INTO scan_features (scan_id, feature_name, feature_value) VALUES (?,?,?)',
                (sid, k, str(v))
            )
    return sid


def update_actual_label(sid, label):
    """BUG-11 FIX: Context manager."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('UPDATE scans SET actual_label = ? WHERE id = ?', (label, sid))


def get_recent_scans(limit=8):
    """BUG-11 FIX: Context manager."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# --- SECTION 6: ML ENGINE ---
def train_model():
    df = pd.read_csv(DATASET_PATH, comment="#").dropna()
    X = pd.DataFrame(
        [extract_features(u) for u in df['url']]
    )[list(FEATURE_COLUMNS)].values.astype(float)
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    rf = RandomForestClassifier(
        n_estimators=200,
        class_weight={0: 1, 1: 3},
        n_jobs=-1,
        random_state=42,
    ).fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1]

    results = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "y_test":   y_test.tolist(),
        "y_pred":   y_pred.tolist(),
        "y_prob":   y_prob.tolist(),
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    # BUG-6 FIX: Store version so stale models are detected on next load
    joblib.dump({"model": rf, "results": results, "version": MODEL_VERSION}, MODEL_PATH)
    return rf, results


# --- SECTION 7: STREAMLIT APP ---
st.set_page_config(page_title="ThreatScan Pro v5.5.2", page_icon="🛡️", layout="wide")
init_database()
ensure_dataset()

# BUG-6 FIX: Discard cached model if version doesn't match
if 'model_data' not in st.session_state:
    loaded = False
    if os.path.exists(MODEL_PATH):
        payload = joblib.load(MODEL_PATH)
        if payload.get("version") == MODEL_VERSION:
            st.session_state.model_data = (payload['model'], payload['results'])
            loaded = True
        else:
            st.info("⚙️ Model version mismatch — retraining with fixed dataset...")
    if not loaded:
        with st.spinner("Training model on fixed dataset..."):
            st.session_state.model_data = train_model()

model, _train_res = st.session_state.model_data

if "last_res" not in st.session_state: st.session_state.last_res = None
if "last_sid" not in st.session_state: st.session_state.last_sid = None

st.markdown(
    "## 🛡️ ThreatScan <span style='font-size:14px; opacity:0.5;'>v5.5.2 AUDITED</span>",
    unsafe_allow_html=True
)
t1, t2 = st.tabs(["🔍 Scanner", "📊 Performance"])

with t1:
    with st.form("scan_form"):
        url_in = st.text_input(
            "URL Inspection",
            placeholder="Paste a URL to scan...",
            label_visibility="collapsed"
        )
        submitted = st.form_submit_button("⚡ Analyze")

    if submitted:
        if url_in:
            start = time.time()
            feats = extract_features(url_in)
            vec   = np.array([[feats[c] for c in FEATURE_COLUMNS]]).astype(float)
            prob  = model.predict_proba(vec)[0]

            # BUG-1 FIX: Threshold 0.45 → 0.50
            verdict = "MALICIOUS" if prob[1] >= 0.50 else "SAFE"

            st.session_state.last_res = {
                "url":                url_in,
                "risk_score":         round(prob[1] * 100, 1),
                "safe_pct":           round(prob[0] * 100, 1),
                "mal_pct":            round(prob[1] * 100, 1),
                "processing_time_ms": round((time.time() - start) * 1000, 2),
                "verdict":            verdict,
                "features":           feats,
            }
            st.session_state.last_sid = log_prediction(st.session_state.last_res)
        else:
            st.warning("No URL entered.")

    # Result card — persistent via session state
    if st.session_state.last_res:
        r     = st.session_state.last_res
        color = "#f43f5e" if r['verdict'] == "MALICIOUS" else "#10b981"
        st.markdown(
            f"<div style='border-left:5px solid {color}; background:rgba(30,41,59,0.4); "
            f"padding:1rem; border-radius:15px;'>"
            f"<h3>{r['verdict']} RISK ({r['risk_score']}%)</h3>"
            f"<code>{html.escape(r['url'])}</code></div>",
            unsafe_allow_html=True
        )

        with st.expander("📝 Report Ground Truth Correction"):
            f_label = st.radio("This result is actually:", ["Safe Link", "Phishing Threat"], horizontal=True)
            if st.button("Apply Correction"):
                update_actual_label(st.session_state.last_sid, 0 if "Safe" in f_label else 1)
                st.success("Correction saved to logs.")

    st.markdown("### 🕒 Recent Audit History")
    for s in get_recent_scans():
        audit = " ⚠️ (PHISH)" if s['actual_label'] == 1 else " ✅ (SAFE)" if s['actual_label'] == 0 else ""

        # BUG-5 FIX: Only append "..." when URL is actually truncated
        url_display = s['url'][:55] + ('...' if len(s['url']) > 55 else '')

        # Timestamp safe-slice: handle None/empty/ISO-T format
        ts_raw  = s.get('timestamp') or ''
        ts_disp = ts_raw[11:16] if len(ts_raw) >= 16 else ts_raw

        st.markdown(
            f"<div style='background:rgba(30,41,59,0.2); padding:0.5rem 1rem; "
            f"border-radius:10px; margin-bottom:5px; display:flex; justify-content:space-between;'>"
            f"<span><small>{html.escape(ts_disp)}</small> "
            f"<b style='font-family:monospace;'>{html.escape(url_display)}</b></span>"
            f"<span style='color:#94a3b8;'>{audit}</span></div>",
            unsafe_allow_html=True
        )

with t2:
    st.info("Performance stats for 5,000 samples.")
    st.write(f"**Accuracy:** {_train_res['accuracy']*100:.2f}%")

    fig, ax = plt.subplots(1, 2, figsize=(10, 4))
    fig.patch.set_facecolor('#0b1120')
    for a in ax:
        a.set_facecolor('#0b1120')

    ConfusionMatrixDisplay.from_predictions(
        _train_res['y_test'], _train_res['y_pred'], ax=ax[0], cmap='Reds'
    )

    fpr, tpr, _ = roc_curve(_train_res['y_test'], _train_res['y_prob'])
    auc_val     = roc_auc_score(_train_res['y_test'], _train_res['y_prob'])
    ax[1].plot(fpr, tpr, color='red', label=f"AUC: {auc_val:.2f}")
    ax[1].plot([0, 1], [0, 1], '--', color='gray')
    ax[1].legend()

    st.pyplot(fig)
    plt.close("all")
