import matplotlib.pyplot as plt

# ERD Text Diagram
erd_text = """
┌────────────────────────────────────────────────────────────────────┐
│                           scans                                    │
├────────────────────────────────────────────────────────────────────┤
│  id (PK)        INTEGER    Auto-incrementing unique scan ID      │
│  url            TEXT       The scanned URL                        │
│  verdict        TEXT       Classification result                  │
│  risk_score     REAL       Risk score (0-100)                     │
│  safe_pct       REAL       Safe probability percentage            │
│  mal_pct        REAL       Malicious probability percentage       │
│  processing_time REAL     Time taken (milliseconds)               │
│  actual_label   INTEGER    User-corrected label (-1,0,1)          │
│  timestamp      DATETIME   Scan date and time                     │
└────────────────────────────────────────────────────────────────────┘
                              │
                              │ 1
                              │
                              │ M
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│                        scan_features                               │
├────────────────────────────────────────────────────────────────────┤
│  id (PK)         INTEGER    Auto-incrementing unique ID           │
│  scan_id (FK)    INTEGER    References scans.id                   │
│  feature_name    TEXT       Name of extracted feature             │
│  feature_value   TEXT       Extracted feature value               │
└────────────────────────────────────────────────────────────────────┘
"""

# Create a figure with the text
fig, ax = plt.subplots(figsize=(12, 8))
ax.text(0.5, 0.5, erd_text, ha='center', va='center', fontsize=10, 
        family='monospace', transform=ax.transAxes)
ax.axis('off')
plt.title("ERD Diagram - SQLite Database", fontsize=14, fontweight='bold')
plt.tight_layout()

# Save the image
plt.savefig('erd_diagram.png', dpi=300, bbox_inches='tight')
print("ERD diagram saved as 'erd_diagram.png'")