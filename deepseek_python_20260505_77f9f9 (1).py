"""
=============================================================================
ThreatScan Pro — Complete Feature Set for Final Year Project
=============================================================================
- Dataset: ~5,000 URLs (balanced, PhishTank/Tranco‑like patterns)
- 36 lexical + host‑based features (including real WHOIS domain age)
- URL unshortening (expands bit.ly, t.co, etc.)
- Models: Random Forest, SVM, Decision Tree (trained & compared)
- Metrics: Accuracy, Precision, Recall, F1, FAR, FRR, AUC
- Visualizations: Confusion Matrix, ROC Curve (all models), Feature Impact per URL
- Batch Analysis (multiple URLs)
- SQLite logging with ground truth correction
- Responsive Sentinel UI
=============================================================================
"""

import os, re, math, time, csv, random, json, sqlite3, html
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Try to import optional libraries gracefully
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests not installed. URL unshortening disabled.")

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    print("Warning: whois not installed. Domain age will be estimated.")

import numpy as np
import pandas as pd
import joblib
import streamlit as st
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, roc_auc_score, ConfusionMatrixDisplay
)

# =============================================================================
# 1. DATASET GENERATION (~5000 URLs, balanced, realistic patterns)
# =============================================================================
# Seed URLs (realistic and diverse)
BENIGN_SEEDS = [
    "google.com", "github.com", "stackoverflow.com", "wikipedia.org", "amazon.com",
    "microsoft.com", "apple.com", "linkedin.com", "nytimes.com", "bbc.com"
]
MALICIOUS_SEEDS = [
    "secure-login.paypa1.com.verify-account.tk", "192.168.10.1/signin", "xn--gogle-pua.com",
    "chase-online-update.xyz", "login.microsoftonline.update.ml", "dhl-parcel-tracking.site",
    "wellsfargo-secure-auth.ga", "amazon-winner-2026.top/claim", "0x58.0x23.0x11.0x01/login",
    "paypal-account-hold.xyz"
]

def augment_urls(seeds, count, is_malicious):
    """Generate varied URLs with different paths, query parameters, and random IDs."""
    augmented = []
    schemes = ["https://"] if not is_malicious else ["http://", "https://"]
    paths = ["", "/login", "/verify", "/account", "/update", "/secure", "/auth", "/signin"]
    while len(augmented) < count:
        domain = random.choice(seeds)
        scheme = random.choice(schemes)
        path = random.choice(paths)
        # Add random query parameter to make each URL unique
        param = f"?{random.choice(['id','user','token','ref'])}={random.randint(1000, 999999)}"
        url = f"{scheme}{domain}{path}{param}"
        if url not in augmented:
            augmented.append(url)
    return augmented

DATASET_PATH = "data/urls.csv"
MODEL_PATH = "models/model_complete.joblib"
DB_PATH = "data/scans.db"

def ensure_dataset():
    if os.path.exists(DATASET_PATH): return
    # Generate 2500 benign + 2500 malicious = 5000 total (adjustable, but keep moderate)
    benign = augment_urls(BENIGN_SEEDS, 2500, False)
    malicious = augment_urls(MALICIOUS_SEEDS, 2500, True)
    rows = [(u, 0) for u in benign] + [(u, 1) for u in malicious]
    random.shuffle(rows)
    os.makedirs("data", exist_ok=True)
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    print(f"Dataset created: {len(rows)} rows")

# =============================================================================
# 2. FEATURE EXTRACTION (36 features including lexical, host-based, entropy)
# =============================================================================
SUSPICIOUS_TLDS = {'xyz','top','click','tk','ml','ga','cf','gq','pw','cc','su','biz','info',
                   'online','site','live','stream','download','loan','review','country','kim',
                   'science','work','party','trade','cricket','date','faith','racing','accountant',
                   'win','bid','men','icu','monster','cyou','buzz','sbs','ru'}
TRUSTED_DOMAINS = {'google.com','youtube.com','facebook.com','microsoft.com','apple.com',
                   'amazon.com','github.com','twitter.com','linkedin.com','wikipedia.org',
                   'instagram.com','netflix.com','stackoverflow.com','reddit.com','paypal.com',
                   'bbc.com','nytimes.com','dropbox.com','mozilla.org','cloudflare.com'}
BRAND_KEYWORDS = ['paypal','google','apple','microsoft','amazon','facebook','instagram','netflix',
                  'ebay','steam','whatsapp','youtube','dropbox','icloud','twitter','chase',
                  'wellsfargo','citibank','bankofamerica','boa','dhl','fedex','usps','ups']
URL_SHORTENERS = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly',
                  'short.io','tiny.cc','cutt.ly','shorturl.at','rb.gy'}
PHISH_RE = re.compile(r'login|signin|verify|account|update|secure|confirm|password|credential|'
                      r'alert|suspend|unlock|recover|reset|billing|payment|invoice', re.I)
EXEC_RE = re.compile(r'\.(exe|bat|cmd|msi|scr|vbs|jar|apk|dmg|sh|ps1|crx|xpi)$', re.I)
SPAM_WORDS = ['free','win','prize','claim','urgent','alert','suspended','verify','confirm',
              'limited','offer','bonus','gift','reward','lucky','congratulation']

def _entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())

def _domain_parts(hostname):
    clean = re.sub(r'^www\.', '', hostname.lower())
    parts = clean.split('.')
    if len(parts) >= 3: return '.'.join(parts[:-2]), parts[-2], parts[-1]
    if len(parts) == 2: return '', parts[0], parts[1]
    return '', hostname, ''

def get_domain_age(domain):
    """Real WHOIS lookup with fallback."""
    if not HAS_WHOIS or not domain: return 365
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if not creation: return 365
        if isinstance(creation, list): creation = creation[0]
        return max((datetime.now() - creation).days, 0)
    except:
        return 365  # fallback

def extract_features(url, expanded_url=None):
    """Extract 36 features from a URL (use expanded URL if provided)."""
    raw = str(url).strip()
    target = expanded_url if expanded_url else raw
    f = {}
    try:
        p = urlparse(target if '://' in target else 'http://' + target)
    except:
        p = urlparse('http://invalid')
    hostname = (p.hostname or '').lower()
    path = p.path or ''
    query = p.query or ''
    scheme = p.scheme or ''
    full_lower = target.lower()
    _, domain, tld = _domain_parts(hostname)
    base = f"{domain}.{tld}" if domain and tld else hostname
    sub, _, _ = _domain_parts(hostname)
    hl = max(len(hostname), 1)

    # A. Protocol
    f['is_https'] = int(scheme == 'https')
    f['is_http'] = int(scheme == 'http')
    # B. Lengths
    f['url_length'] = len(target)
    f['hostname_length'] = len(hostname)
    f['path_length'] = len(path)
    f['query_length'] = len(query)
    # C. Special chars
    f['dot_count'] = hostname.count('.')
    f['hyphen_count'] = hostname.count('-')
    f['underscore_count'] = target.count('_')
    f['at_sign'] = int('@' in target)
    f['double_slash'] = int('//' in path)
    f['question_mark'] = int('?' in target)
    f['ampersand_count'] = query.count('&')
    f['equals_count'] = query.count('=')
    f['percent_count'] = len(re.findall(r'%[0-9a-fA-F]{2}', target))
    f['hash_count'] = int('#' in target)
    # D. Ratios
    f['digit_ratio'] = round(sum(c.isdigit() for c in hostname) / hl, 4)
    f['alpha_ratio'] = round(sum(c.isalpha() for c in hostname) / hl, 4)
    # E. Domain structure
    f['subdomain_count'] = len(sub.split('.')) if sub else 0
    f['suspicious_tld'] = int(tld in SUSPICIOUS_TLDS)
    f['tld_length'] = len(tld)
    f['is_ip_host'] = int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname)))
    f['trusted_domain'] = int(base in TRUSTED_DOMAINS)
    brand_hit = any(b in hostname for b in BRAND_KEYWORDS)
    f['brand_in_domain'] = int(brand_hit and base not in TRUSTED_DOMAINS)
    f['digit_in_word'] = int(bool(re.search(r'[a-z]\d[a-z]', hostname)))
    # F. Path signals
    f['phish_path_kw'] = int(bool(PHISH_RE.search(path)))
    f['executable_ext'] = int(bool(EXEC_RE.search(path)))
    f['path_depth'] = path.count('/')
    f['path_has_ip'] = int(bool(re.search(r'/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', path)))
    # G. Query signals
    try: f['param_count'] = len(parse_qs(query))
    except: f['param_count'] = 0
    # H. Entropy
    f['hostname_entropy'] = round(_entropy(hostname), 4)
    f['path_entropy'] = round(_entropy(path), 4)
    # I. Reputation
    f['is_shortener'] = int(hostname in URL_SHORTENERS)
    f['spam_keyword_count'] = sum(w in full_lower for w in SPAM_WORDS)
    f['has_punycode'] = int('xn--' in hostname)
    f['domain_age_days'] = get_domain_age(base)
    return f

FEATURE_COLUMNS = list(extract_features("http://example.com").keys())  # 36 features

# =============================================================================
# 3. URL UNSHORTENING (with fallback if requests not installed)
# =============================================================================
def is_shortened_url(url):
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'): domain = domain[4:]
        return any(short in domain for short in URL_SHORTENERS)
    except:
        return False

def unshorten_url(url):
    if not HAS_REQUESTS or not is_shortened_url(url):
        return url
    try:
        if not url.startswith(('http://','https://')): url = 'https://' + url
        resp = requests.head(url, allow_redirects=True, timeout=8)
        if resp.status_code == 200 and resp.url:
            return resp.url
        resp = requests.get(url, allow_redirects=True, timeout=8)
        if resp.status_code == 200 and resp.url:
            return resp.url
        return url
    except:
        return url

def safe_unshorten(url):
    was = is_shortened_url(url)
    expanded = unshorten_url(url) if was else url
    return url, expanded, was

# =============================================================================
# 4. SQLite DATABASE & LOGGING
# =============================================================================
def init_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT, expanded_url TEXT, verdict TEXT,
        risk_score REAL, safe_pct REAL, mal_pct REAL,
        processing_time REAL, actual_label INTEGER DEFAULT -1,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS scan_features (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER, feature_name TEXT, feature_value TEXT
    )''')
    conn.commit()
    conn.close()

def log_prediction(data):
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute('''INSERT INTO scans (url, expanded_url, verdict, risk_score, safe_pct, mal_pct, processing_time)
                 VALUES (?,?,?,?,?,?,?)''',
              (data['url'], data.get('expanded_url',''), data['verdict'],
               data['risk_score'], data['safe_pct'], data['mal_pct'], data['processing_time_ms']))
    sid = c.lastrowid
    for name, val in data['features'].items():
        c.execute('INSERT INTO scan_features (scan_id, feature_name, feature_value) VALUES (?,?,?)',
                  (sid, name, str(val)))
    conn.commit(); conn.close()
    return sid

def update_actual_label(sid, label):
    conn = sqlite3.connect(DB_PATH); conn.execute('UPDATE scans SET actual_label = ? WHERE id = ?', (label, sid)); conn.commit(); conn.close()

def get_recent_scans(limit=10):
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# =============================================================================
# 5. MODEL TRAINING (All Three Models + FAR/FRR)
# =============================================================================
def calculate_far_frr(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    far = fp / (fp + tn) if (fp + tn) > 0 else 0
    frr = fn / (fn + tp) if (fn + tp) > 0 else 0
    return far, frr

def train_all_models():
    df = pd.read_csv(DATASET_PATH).dropna()
    X = pd.DataFrame([extract_features(u) for u in df['url']])[FEATURE_COLUMNS].fillna(0).values.astype(float)
    y = df['label'].values
    # Replace missing domain_age_days (if any -1) with median
    col_idx = FEATURE_COLUMNS.index('domain_age_days')
    median_age = np.median(X[:, col_idx][X[:, col_idx] >= 0]) if np.any(X[:, col_idx] >= 0) else 365
    X[X[:, col_idx] == -1, col_idx] = median_age

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    models = {
        "Random Forest": RandomForestClassifier(n_estimators=200, max_depth=12, class_weight='balanced', random_state=42, n_jobs=-1),
        "SVM": SVC(kernel='rbf', probability=True, class_weight='balanced', random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=12, class_weight='balanced', random_state=42)
    }

    results = {}
    best_model = None
    best_acc = 0

    for name, clf in models.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else None

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        far, frr = calculate_far_frr(y_test, y_pred)
        auc = roc_auc_score(y_test, y_prob) if y_prob is not None else 0

        results[name] = {
            "model": clf,
            "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
            "far": far, "frr": frr, "auc": auc,
            "y_test": y_test, "y_pred": y_pred, "y_prob": y_prob
        }
        if acc > best_acc:
            best_acc = acc
            best_model = clf

    # Save best model and all results for later use
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({"best_model": best_model, "all_results": results, "feature_columns": FEATURE_COLUMNS}, MODEL_PATH)
    return results, best_model

@st.cache_resource
def load_models():
    ensure_dataset()
    if not os.path.exists(MODEL_PATH):
        results, best_model = train_all_models()
        return results, best_model, FEATURE_COLUMNS
    payload = joblib.load(MODEL_PATH)
    return payload["all_results"], payload["best_model"], payload["feature_columns"]

# =============================================================================
# 6. PREDICTION FUNCTION (with unshortening & feature impact)
# =============================================================================
def predict_url(url, model, feat_cols, log_to_db=True):
    start = time.time()
    original, expanded, was_short = safe_unshorten(url)
    feats = extract_features(original, expanded if was_short else None)
    X = np.array([feats.get(c,0) for c in feat_cols]).reshape(1,-1)
    prob = model.predict_proba(X)[0]
    safe_pct = round(prob[0]*100,1)
    mal_pct = round(prob[1]*100,1)
    verdict = "MALICIOUS" if mal_pct >= 50 else ("SUSPICIOUS" if mal_pct >= 30 else "SAFE")
    proc_time = round((time.time() - start)*1000, 2)

    # Feature impact for UI (simple heuristic)
    impact = {
        "Suspicious TLD": 85 if feats.get('suspicious_tld') else 5,
        "IP Host": 90 if feats.get('is_ip_host') else 2,
        "Brand Spoof": 75 if feats.get('brand_in_domain') else 4,
        "Phish Keywords": 80 if feats.get('phish_path_kw') else 10,
        "Shortener": 60 if feats.get('is_shortener') else 5,
        "Young Domain": 70 if feats.get('domain_age_days',365) < 30 else 5,
        "Spam Words": min(feats.get('spam_keyword_count',0)*20,100),
    }
    # Signal list for display
    signals = []
    if feats.get('is_https'): signals.append(("✅ HTTPS", "good"))
    else: signals.append(("❌ No HTTPS", "bad"))
    if feats.get('suspicious_tld'): signals.append(("⚠️ Suspicious TLD", "bad"))
    if feats.get('is_ip_host'): signals.append(("⚠️ IP Address", "bad"))
    if feats.get('brand_in_domain'): signals.append(("⚠️ Brand Impersonation", "bad"))
    if feats.get('phish_path_kw'): signals.append(("⚠️ Phish Path", "bad"))
    if feats.get('is_shortener'): signals.append(("🔗 Shortener", "bad"))
    if not any(k=="bad" for _,k in signals): signals.append(("✅ No threats found", "good"))

    result = {
        "url": original, "expanded_url": expanded, "was_shortened": was_short,
        "verdict": verdict, "risk_score": mal_pct, "safe_pct": safe_pct, "mal_pct": mal_pct,
        "processing_time_ms": proc_time, "features": feats, "impact": impact, "signals": signals
    }
    if log_to_db:
        log_prediction(result)
    return result

def get_hostname(url):
    try: return urlparse(url).hostname or "unknown"
    except: return "unknown"

# =============================================================================
# 7. STREAMLIT UI
# =============================================================================
init_database()
st.set_page_config(page_title="ThreatScan Pro", page_icon="🛡️", layout="wide")

# Custom CSS (same as before, shortened for brevity)
st.markdown("""
<style>
.stApp { background-color: #0b0f19; color: #e2e8f0; }
header, #MainMenu, footer { visibility: hidden; }
.block-container { padding-top: 1rem; max-width: 1200px; }
.sentinel-nav { display: flex; justify-content: space-between; padding: 1rem 0; border-bottom: 1px solid #1e293b; margin-bottom: 2rem; }
.nav-brand { font-size: 1.5rem; font-weight: 700; color: white; display: flex; gap: 10px; align-items: center; }
.nav-sub { color: #94a3b8; font-size: 0.9rem; }
.inspect-card { background: #111827; border: 1px solid #1e293b; border-radius: 16px; padding: 2rem; text-align: center; margin-bottom: 2rem; }
.stTextInput>div>div>input { background: #0b0f19; border: 1px solid #1e293b; color: white; }
.stButton>button { background: #1e293b; color: white; border-radius: 8px; }
.result-card { background: #111827; border-radius: 16px; padding: 1rem; margin: 1rem 0; border-left: 4px solid; }
.result-safe { border-left-color: #10b981; }
.result-malicious { border-left-color: #ef4444; }
.result-suspicious { border-left-color: #f59e0b; }
.verdict { font-size: 1.8rem; font-weight: 700; }
.history-item { background: #111827; border-radius: 8px; padding: 0.5rem; margin-bottom: 0.5rem; border: 1px solid #1e293b; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="sentinel-nav">
    <div class="nav-brand"><span style="font-size:1.5rem;">🛡️</span> ThreatScan Pro</div>
    <div class="nav-sub">Malicious URL Detector | 36 Features | 3 Models</div>
</div>
""", unsafe_allow_html=True)

# Sidebar: recent scans
with st.sidebar:
    st.markdown("### 🕒 Recent Scans")
    recent = get_recent_scans(8)
    if not recent:
        st.markdown("*No scans yet*")
    else:
        for s in recent:
            vc = "#f87171" if s['verdict'] in ["MALICIOUS","CRITICAL"] else "#10b981"
            st.markdown(f'<div class="history-item"><span style="color:{vc}">▸</span> {s["verdict"]}<br/><small>{s["url"][:40]}…</small></div>', unsafe_allow_html=True)
    st.markdown("---")
    st.caption("Powered by scikit-learn | Random Forest, SVM, DT")

# Load models
all_results, best_model, feat_cols = load_models()

# Tabs
tab1, tab2, tab3 = st.tabs(["🔍 Single URL", "📄 Batch Analysis", "📊 Model Performance"])

# ---------------------------- TAB 1: Single URL ----------------------------
with tab1:
    st.markdown('<div class="inspect-card"><div style="font-size:2rem;">🛡️</div><div class="inspect-title">Ready for Inspection</div></div>', unsafe_allow_html=True)
    col1, col2 = st.columns([4,1])
    with col1:
        url_input = st.text_input("", placeholder="https://example.com/login", label_visibility="collapsed")
    with col2:
        analyze = st.button("🔍 Analyze", use_container_width=True)

    if analyze and url_input:
        with st.spinner("Analyzing..."):
            result = predict_url(url_input, best_model, feat_cols, log_to_db=True)
            st.session_state['last_result'] = result
        # Result display
        verdict = result['verdict']
        border_color = "#10b981" if verdict == "SAFE" else ("#f59e0b" if verdict == "SUSPICIOUS" else "#ef4444")
        st.markdown(f"""
        <div class="result-card result-{verdict.lower()}">
            <div class="verdict">{verdict} RISK</div>
            <div>Confidence: {result['risk_score']}% | Processing: {result['processing_time_ms']}ms</div>
            <div>Target Host: {get_hostname(url_input)}</div>
            <div>{'🔗 Shortened URL expanded' if result['was_shortened'] else ''}</div>
        </div>
        """, unsafe_allow_html=True)
        # Metrics
        cola, colb, colc, cold = st.columns(4)
        cola.metric("Safe Probability", f"{result['safe_pct']}%")
        colb.metric("Malicious Probability", f"{result['mal_pct']}%")
        colc.metric("HTTPS", "Yes" if result['features'].get('is_https') else "No")
        cold.metric("Domain Age", f"{result['features'].get('domain_age_days',365)} days")
        # Threat indicators
        st.markdown("#### 🎯 Threat Indicators")
        inds = [("Suspicious TLD", result['features'].get('suspicious_tld')),
                ("IP as Host", result['features'].get('is_ip_host')),
                ("Brand Impersonation", result['features'].get('brand_in_domain')),
                ("Phish Path Keywords", result['features'].get('phish_path_kw')),
                ("No HTTPS", not result['features'].get('is_https')),
                ("Shortener", result['features'].get('is_shortener')),
                ("Executable Extension", result['features'].get('executable_ext')),
                ("Young Domain (<30 days)", result['features'].get('domain_age_days',365) < 30)]
        for text, cond in inds:
            if cond: st.markdown(f"- {text}")
        if not any(cond for _,cond in inds): st.markdown("- No significant indicators found")
        # Feature Impact Graph
        st.markdown("#### 📊 Feature Impact")
        impact_items = [(k,v) for k,v in result['impact'].items() if v > 5]
        if impact_items:
            impact_items.sort(key=lambda x: x[1])
            fig, ax = plt.subplots(figsize=(6,2.5))
            fig.patch.set_facecolor('#111827')
            ax.set_facecolor('#111827')
            ax.barh([i[0] for i in impact_items], [i[1] for i in impact_items], color='#4f46e5')
            ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
            ax.tick_params(colors='white')
            st.pyplot(fig)
            plt.close(fig)
        # Full features expander
        with st.expander("View Full Feature Vector (36 features)"):
            st.dataframe(pd.DataFrame(result['features'].items(), columns=["Feature","Value"]).set_index("Feature"), height=400)
    elif analyze:
        st.warning("Please enter a URL.")

# ---------------------------- TAB 2: Batch Analysis ----------------------------
with tab2:
    st.markdown("### Batch Processing")
    batch_text = st.text_area("Enter URLs (one per line)", height=200)
    if st.button("Scan Batch"):
        urls = [u.strip() for u in batch_text.splitlines() if u.strip()]
        if not urls:
            st.warning("No URLs entered")
        else:
            results = []
            for u in urls:
                r = predict_url(u, best_model, feat_cols, log_to_db=False)
                results.append({"URL": u[:70], "Verdict": r['verdict'], "Risk Score": r['risk_score']})
            st.dataframe(pd.DataFrame(results), use_container_width=True)

# ---------------------------- TAB 3: Model Performance ----------------------------
with tab3:
    st.markdown("### Model Comparison (Random Forest, SVM, Decision Tree)")
    # Build comparison table
    comp_data = []
    for name, res in all_results.items():
        comp_data.append({
            "Model": name,
            "Accuracy": f"{res['accuracy']*100:.1f}%",
            "Precision": f"{res['precision']*100:.1f}%" if 'precision' in res else "N/A",
            "Recall": f"{res['recall']*100:.1f}%" if 'recall' in res else "N/A",
            "F1": f"{res['f1']*100:.1f}%" if 'f1' in res else "N/A",
            "FAR": f"{res['far']*100:.1f}%",
            "FRR": f"{res['frr']*100:.1f}%",
            "AUC": f"{res['auc']:.3f}"
        })
    st.dataframe(pd.DataFrame(comp_data), use_container_width=True)
    st.caption("Targets: Accuracy ≥95%, FAR ≤2%, FRR ≤3%")
    # Confusion Matrix & ROC for each model (show first two models side by side)
    models_to_show = list(all_results.keys())
    for i in range(0, len(models_to_show), 2):
        cols = st.columns(2)
        for j, name in enumerate(models_to_show[i:i+2]):
            with cols[j]:
                st.markdown(f"#### {name}")
                res = all_results[name]
                y_test, y_pred, y_prob = res['y_test'], res['y_pred'], res['y_prob']
                if y_prob is not None:
                    fig, ax = plt.subplots(1,2, figsize=(8,3))
                    fig.patch.set_facecolor('#111827')
                    for a in ax: a.set_facecolor('#111827')
                    # Confusion Matrix
                    cm = confusion_matrix(y_test, y_pred)
                    ConfusionMatrixDisplay(cm, display_labels=["Benign","Malicious"]).plot(ax=ax[0], colorbar=False, cmap='Blues')
                    ax[0].set_title("Confusion Matrix", color='white')
                    ax[0].tick_params(colors='white')
                    # ROC
                    fpr, tpr, _ = roc_curve(y_test, y_prob)
                    auc = res['auc']
                    ax[1].plot(fpr, tpr, color='#4f46e5', label=f"AUC={auc:.3f}")
                    ax[1].plot([0,1],[0,1],'k--', alpha=0.3)
                    ax[1].set_title("ROC Curve", color='white')
                    ax[1].legend(loc='lower right')
                    ax[1].tick_params(colors='white')
                    st.pyplot(fig)
                    plt.close(fig)
                else:
                    st.write("Probability not available for this model.")