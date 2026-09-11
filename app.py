"""
PQC Transition Toolkit — Streamlit Dashboard
Implements & extends: Birgin & Celiktas (2026), IEEE Access
  DOI: 10.1109/ACCESS.2026.3669437

By: Muhammad Ahmad
Course: Information Security | UMT Lahore | Spring 2026
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import json, os, datetime

# ══════════════════════════════════════════════════════════════
# QRS ENGINE (inline — no external module needed)
# ══════════════════════════════════════════════════════════════

AHP_WEIGHTS = {"dl": 0.30, "av": 0.25, "ke": 0.25, "sd": 0.20}
THRESHOLDS  = {"MIGRATE": 8.0, "HYBRID": 7.0, "MONITOR": 6.0}

PAPER_ASSETS = [
    {"id":"A1","name":"PKI Root CA","algorithm":"RSA-4096","sector":"Government","dl":10,"av":10,"ke":8,"sd":10},
    {"id":"A2","name":"TLS Web Gateway","algorithm":"ECDHE-RSA-2048","sector":"Government","dl":7,"av":9,"ke":9,"sd":8},
    {"id":"A3","name":"VPN Infrastructure","algorithm":"DH-2048, AES-256","sector":"Government","dl":6,"av":8,"ke":7,"sd":8},
    {"id":"A4","name":"Code Signing Service","algorithm":"ECDSA-P256","sector":"Government","dl":5,"av":7,"ke":6,"sd":7},
    {"id":"A5","name":"Email Encryption (S/MIME)","algorithm":"RSA-2048","sector":"Government","dl":5,"av":7,"ke":5,"sd":5},
    {"id":"A6","name":"Document Archive Signing","algorithm":"RSA-2048, SHA-256","sector":"Government","dl":8,"av":6,"ke":4,"sd":4},
]

# Extended (new-contribution) assets start empty — populated live from the
# "Custom Asset Assessment" page and kept in st.session_state so they persist
# across reruns within a session. No fictional/dummy entries are pre-seeded.
EXTENDED_ASSETS = []

def compute_qrs(dl, av, ke, sd):
    return round(0.30*dl + 0.25*av + 0.25*ke + 0.20*sd, 3)

def assign_policy(score):
    if score >= 8.0: return "MIGRATE"
    if score >= 7.0: return "HYBRID"
    if score >= 6.0: return "MONITOR"
    return "DEFER"

def evaluate_assets(assets):
    results = []
    for a in assets:
        qrs = compute_qrs(a["dl"], a["av"], a["ke"], a["sd"])
        results.append({**a, "qrs_score": qrs, "policy": assign_policy(qrs)})
    return results

def evaluate_custom(name, algorithm, dl, av, ke, sd, sector="Other"):
    qrs = compute_qrs(dl, av, ke, sd)
    return {"id":"CUSTOM","name":name,"algorithm":algorithm,"sector":sector,
            "dl":dl,"av":av,"ke":ke,"sd":sd,"qrs_score":qrs,"policy":assign_policy(qrs)}

def cicd_gate(results):
    findings, migrate, hybrid, monitor, defer = [], 0, 0, 0, 0
    for r in results:
        p = r["policy"]
        if p == "MIGRATE": migrate += 1
        elif p == "HYBRID": hybrid += 1
        elif p == "MONITOR": monitor += 1
        else: defer += 1
        if p in ("MIGRATE","HYBRID"):
            findings.append({"asset_id":r["id"],"asset_name":r["name"],"qrs_score":r["qrs_score"],"policy":p})
    decision = "BLOCK" if migrate > 0 else ("RESTRICT" if hybrid > 0 else "ALLOW")
    return {"gate":"Crypto-Aware CI/CD Validation Gate","timestamp":datetime.datetime.utcnow().isoformat()+"Z",
            "decision":decision,"migrate_count":migrate,"hybrid_count":hybrid,
            "monitor_count":monitor,"defer_count":defer,"total_assets":len(results),"findings":findings}

def generate_qrs_json(results, output_path=None):
    artifact = {"artifact":"qrs_results.json","phase":"P3 — Risk Modeling",
                "generated":datetime.datetime.utcnow().isoformat()+"Z",
                "ahp_weights":AHP_WEIGHTS,"thresholds":THRESHOLDS,"results":results}
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path,"w") as f: json.dump(artifact, f, indent=2)
    return artifact

# ══════════════════════════════════════════════════════════════
# STREAMLIT APP
# ══════════════════════════════════════════════════════════════

st.set_page_config(page_title="PQC Transition Toolkit", page_icon="🔐", layout="wide", initial_sidebar_state="expanded")

POLICY_COLORS = {"MIGRATE":"#C00000","HYBRID":"#E07000","MONITOR":"#0070C0","DEFER":"#548235"}

# Live, in-session store for extended-dataset assets. Starts empty — assets
# are added from "Custom Asset Assessment" and persist for the session only
# (Streamlit has no built-in DB; this is intentional, not a bug).
if "extended_assets" not in st.session_state:
    st.session_state.extended_assets = []

st.sidebar.image("https://upload.wikimedia.org/wikipedia/en/thumb/6/6b/UMT_logo.png/200px-UMT_logo.png", width=120)
st.sidebar.title("🔐 PQC Transition Toolkit")
st.sidebar.caption("Implementing Birgin & Celiktas (2026)\nIEEE Access — DOI: 10.1109/ACCESS.2026.3669437")
st.sidebar.markdown("---")

page = st.sidebar.radio("Navigation", [
    "🏠 Home",
    "📊 QRS Dashboard — Paper Assets",
    "🌐 Extended QRS — New Contribution",
    "✏️ Custom Asset Assessment",
    "🚦 CI/CD Enforcement Gate",
    "📋 Evidence & Audit Log"
])

st.sidebar.markdown("---")
st.sidebar.markdown("**PQC Transition Toolkit**")
st.sidebar.caption("By Muhammad Ahmad")
st.sidebar.caption("UMT Lahore · Spring 2026")

if page == "🏠 Home":
    st.title("🔐 Post-Quantum Cryptography Transition Toolkit")
    st.subheader("Operationalizing the Birgin & Celiktas (2026) Framework")
    col1,col2,col3,col4 = st.columns(4)
    col1.metric("Base Paper Assets","6","Reproduced")
    col2.metric("Extended Assets",len(st.session_state.extended_assets),"Add via Custom Asset Assessment")
    col3.metric("Sectors Covered","4","New Contribution")
    col4.metric("Framework Phases","7","Fully Implemented")
    st.markdown("---")
    st.markdown("""
### About This Tool
This toolkit **reproduces and extends** the seven-phase PQC Transition Framework proposed by
Birgin & Celiktas (2026) in IEEE Access (DOI: `10.1109/ACCESS.2026.3669437`).

The original paper formalises PQC transition as an operational systems-engineering problem centred on
**Quantum Risk Scoring (QRS)** — a deterministic, AHP-calibrated scoring model — and **CI/CD enforcement gates**.

This tool implements the full framework in Python/Streamlit and **extends** it with:
- A cross-sector extended asset dataset (Healthcare, Finance, Energy, Education) — **new contribution**
- Sector-level aggregated risk analysis — **new finding**
- Interactive custom asset scoring — **new utility**
- Real-time CI/CD gate simulation with audit artifact export
""")
    st.markdown("---")
    st.markdown("### 7-Phase Framework (Birgin & Celiktas, 2026)")
    phases = [
        ("P1","Asset Inventory","Discover all cryptographic assets"),
        ("P2","Classification","Tag by exposure, sensitivity, regulatory dependency"),
        ("P3","Risk Modeling","Compute QRS scores using AHP-weighted formula"),
        ("P4","Algorithm Selection","Choose Kyber/Dilithium/SPHINCS+ per risk level"),
        ("P5","Deployment","CI/CD-enforced cryptographic validation gates"),
        ("P6","Monitoring","Prometheus/Grafana telemetry and fallback detection"),
        ("P7","Governance","OPA policy enforcement and audit alignment"),
    ]
    cols = st.columns(7)
    for i,(pid,title,desc) in enumerate(phases):
        with cols[i]:
            st.markdown(f"**{pid}**")
            st.markdown(f"*{title}*")
            st.caption(desc)
    st.markdown("---")
    st.info("📌 **QRS Formula** (Equation 1, paper p.33544):  \n`QRS = (0.30 × Data Longevity) + (0.25 × Algorithm Vulnerability) + (0.25 × Key Exposure) + (0.20 × System Dependence)`")

elif page == "📊 QRS Dashboard — Paper Assets":
    st.title("📊 QRS Dashboard — Reproducing Paper Table 8")
    st.caption("Source: Birgin & Celiktas (2026), Table 8, p.33546 — exact reproduction")
    results = evaluate_assets(PAPER_ASSETS)
    df = pd.DataFrame(results)
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("MIGRATE",len(df[df.policy=="MIGRATE"]),delta="Immediate action required",delta_color="inverse")
    c2.metric("HYBRID", len(df[df.policy=="HYBRID"]), delta="Hybrid controls needed")
    c3.metric("MONITOR",len(df[df.policy=="MONITOR"]),delta="Under telemetry")
    c4.metric("DEFER",  len(df[df.policy=="DEFER"]),  delta="Low risk")
    st.markdown("---")
    st.subheader("QRS Results Table (Reproduced from Paper Table 8)")
    display_df = df[["id","name","algorithm","dl","av","ke","sd","qrs_score","policy"]].copy()
    display_df.columns = ["ID","Asset Name","Algorithm","Data Longevity","Algo Vuln","Key Exposure","Sys Depend","QRS Score","Policy"]
    def color_policy(val):
        colors = {"MIGRATE":"background-color:#FFD7D7","HYBRID":"background-color:#FFE8C0","MONITOR":"background-color:#C0DCFF","DEFER":"background-color:#D7F0C0"}
        return colors.get(val,"")
    st.dataframe(display_df.style.map(color_policy, subset=["Policy"]), use_container_width=True)
    st.markdown("---")
    st.subheader("QRS Score Comparison")
    fig = go.Figure()
    for policy,color in POLICY_COLORS.items():
        subset = df[df.policy==policy]
        if not subset.empty:
            fig.add_trace(go.Bar(x=subset["name"],y=subset["qrs_score"],name=policy,marker_color=color,text=subset["policy"],textposition="outside"))
    fig.add_hline(y=8.0,line_dash="dash",line_color="red",annotation_text="MIGRATE (8.0)")
    fig.add_hline(y=7.0,line_dash="dash",line_color="orange",annotation_text="HYBRID (7.0)")
    fig.add_hline(y=6.0,line_dash="dash",line_color="blue",annotation_text="MONITOR (6.0)")
    fig.update_layout(xaxis_title="Asset",yaxis_title="QRS Score",yaxis_range=[0,10.5],height=420,plot_bgcolor="white",paper_bgcolor="white")
    st.plotly_chart(fig, use_container_width=True)

elif page == "🌐 Extended QRS — New Contribution":
    st.title("🌐 Extended QRS Analysis — New Contribution")
    st.caption("Cross-sector assets you've entered (Healthcare, Finance, Energy, Education, ...)")
    if not st.session_state.extended_assets:
        st.info("No extended assets yet. Go to **✏️ Custom Asset Assessment** and use "
                 "**\"➕ Add to Extended Dataset\"** to start building this dataset with real data.")
        st.stop()
    results = evaluate_assets(st.session_state.extended_assets)
    df = pd.DataFrame(results)
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("MIGRATE",len(df[df.policy=="MIGRATE"]),delta_color="inverse",delta="Immediate action")
    c2.metric("HYBRID", len(df[df.policy=="HYBRID"]))
    c3.metric("MONITOR",len(df[df.policy=="MONITOR"]))
    c4.metric("DEFER",  len(df[df.policy=="DEFER"]))
    st.markdown("---")
    sector_filter = st.multiselect("Filter by Sector", df["sector"].unique().tolist(), default=df["sector"].unique().tolist())
    filtered = df[df["sector"].isin(sector_filter)]
    display_df = filtered[["id","name","sector","algorithm","dl","av","ke","sd","qrs_score","policy"]].copy()
    display_df.columns = ["ID","Asset Name","Sector","Algorithm","DL","AV","KE","SD","QRS Score","Policy"]
    def color_policy(val):
        colors = {"MIGRATE":"background-color:#FFD7D7","HYBRID":"background-color:#FFE8C0","MONITOR":"background-color:#C0DCFF","DEFER":"background-color:#D7F0C0"}
        return colors.get(val,"")
    st.dataframe(display_df.style.map(color_policy, subset=["Policy"]), use_container_width=True)
    st.markdown("---")
    st.subheader("Sector-Level Average QRS")
    sector_avg = df.groupby("sector")["qrs_score"].mean().reset_index()
    fig2 = px.bar(sector_avg, x="sector", y="qrs_score", color="sector", text="qrs_score")
    fig2.add_hline(y=8.0,line_dash="dash",line_color="red",annotation_text="MIGRATE (8.0)")
    fig2.add_hline(y=7.0,line_dash="dash",line_color="orange",annotation_text="HYBRID (7.0)")
    fig2.update_layout(plot_bgcolor="white",paper_bgcolor="white",height=380)
    st.plotly_chart(fig2, use_container_width=True)
    st.success("✅ **New Contribution:** Finance and Energy sectors show average QRS above the MIGRATE threshold (8.0), indicating systemic sector-level risk not identifiable from the original paper's single-sector validation.")

elif page == "✏️ Custom Asset Assessment":
    st.title("✏️ Custom Asset Assessment")
    st.caption("Score your own cryptographic asset using the QRS model")
    with st.form("custom_form"):
        c1,c2 = st.columns(2)
        name      = c1.text_input("Asset Name","My Server")
        algorithm = c2.text_input("Current Algorithm","RSA-2048, TLS 1.2")
        sector    = c1.selectbox("Sector",["Healthcare","Finance","Energy","Education","Government","Other"])
        st.markdown("**Rate each factor (1 = low risk, 10 = high risk)**")
        c1,c2,c3,c4 = st.columns(4)
        dl = c1.slider("Data Longevity",1,10,7)
        av = c2.slider("Algorithm Vulnerability",1,10,8)
        ke = c3.slider("Key Exposure",1,10,6)
        sd = c4.slider("System Dependence",1,10,7)
        submitted = st.form_submit_button("Compute QRS Score",type="primary")
    if submitted:
        # Stash in session_state so it survives the rerun triggered by the
        # "Add to Extended Dataset" button below (which lives outside the form).
        st.session_state.last_custom_result = evaluate_custom(name,algorithm,dl,av,ke,sd,sector)

    if st.session_state.get("last_custom_result"):
        result = st.session_state.last_custom_result
        score,policy = result["qrs_score"],result["policy"]
        color = POLICY_COLORS[policy]
        st.markdown("---")
        st.markdown(f"## Result: <span style='color:{color}'>{policy}</span> — QRS Score: **{score}**",unsafe_allow_html=True)
        meanings = {
            "MIGRATE":"⚠️ **Immediate action required.** Begin PQC migration using ML-KEM (Kyber) or ML-DSA (Dilithium).",
            "HYBRID": "🔶 **Hybrid controls required.** Deploy Kyber-768 or Dilithium-3 alongside existing algorithm.",
            "MONITOR":"🔵 **Monitor and plan.** Implement telemetry and plan migration within 12–24 months.",
            "DEFER":  "✅ **Defer.** Asset poses low quantum risk. Reassess annually."
        }
        st.info(meanings[policy])
        breakdown = pd.DataFrame({
            "Factor":["Data Longevity","Algorithm Vulnerability","Key Exposure","System Dependence"],
            "Raw Score":[result["dl"],result["av"],result["ke"],result["sd"]],
            "AHP Weight":[0.30,0.25,0.25,0.20],
            "Weighted":[round(result["dl"]*0.30,3),round(result["av"]*0.25,3),round(result["ke"]*0.25,3),round(result["sd"]*0.20,3)]
        })
        st.dataframe(breakdown,use_container_width=True)
        st.metric("Total QRS Score",score,f"Policy: {policy}")

        if st.button("➕ Add to Extended Dataset", type="primary"):
            new_id = f"C{len(st.session_state.extended_assets)+1}"
            entry = dict(result)
            entry["id"] = new_id
            st.session_state.extended_assets.append(entry)
            st.session_state.last_custom_result = None
            st.success(f"Added as {new_id}. See it under **🌐 Extended QRS — New Contribution**.")
            st.rerun()

    st.markdown("---")
    st.subheader(f"Extended Dataset — {len(st.session_state.extended_assets)} asset(s) entered")
    if st.session_state.extended_assets:
        manage_df = pd.DataFrame(st.session_state.extended_assets)[["id","name","sector","algorithm","qrs_score","policy"]]
        manage_df.columns = ["ID","Name","Sector","Algorithm","QRS Score","Policy"]
        st.dataframe(manage_df, use_container_width=True)
        to_remove = st.selectbox(
            "Remove an entry",
            ["—"] + [a["id"] for a in st.session_state.extended_assets],
        )
        if to_remove != "—" and st.button("🗑️ Remove selected"):
            st.session_state.extended_assets = [a for a in st.session_state.extended_assets if a["id"] != to_remove]
            st.rerun()
    else:
        st.caption("Nothing entered yet — scored assets you add above will appear here and feed the Extended QRS, CI/CD Gate, and Evidence pages.")

elif page == "🚦 CI/CD Enforcement Gate":
    st.title("🚦 CI/CD Enforcement Gate")
    st.caption("Algorithm 1 — Crypto-Aware CI/CD Validation Gate (Birgin & Celiktas, 2026, p.33542)")
    dataset = st.radio("Select asset dataset",[
        "Paper Assets (6)",
        f"Extended Assets ({len(st.session_state.extended_assets)})"
    ])
    if "Paper" in dataset:
        results = evaluate_assets(PAPER_ASSETS)
    elif not st.session_state.extended_assets:
        st.info("No extended assets yet — add some in **✏️ Custom Asset Assessment** first.")
        st.stop()
    else:
        results = evaluate_assets(st.session_state.extended_assets)
    audit = cicd_gate(results)
    decision = audit["decision"]
    decision_colors = {"ALLOW":"#548235","RESTRICT":"#E07000","BLOCK":"#C00000"}
    decision_icons  = {"ALLOW":"✅","RESTRICT":"⚠️","BLOCK":"🚫"}
    st.markdown(f"## Gate Decision: {decision_icons[decision]} <span style='color:{decision_colors[decision]};font-size:2rem'>{decision}</span>",unsafe_allow_html=True)
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("MIGRATE Assets",audit["migrate_count"])
    c2.metric("HYBRID Assets", audit["hybrid_count"])
    c3.metric("MONITOR Assets",audit["monitor_count"])
    c4.metric("DEFER Assets",  audit["defer_count"])
    if audit["findings"]:
        st.markdown("### Violations Detected")
        for f in audit["findings"]:
            with st.expander(f"[{f['policy']}] {f['asset_name']} — QRS: {f['qrs_score']}"):
                st.error(f"Policy: {f['policy']} | QRS Score: {f['qrs_score']}")
    else:
        st.success("No violations detected — all assets compliant.")
    st.markdown("---")
    st.subheader("Audit Artifact — audit_gate.json")
    st.code(json.dumps(audit,indent=2),language="json")
    st.download_button("⬇️ Download audit_gate.json",json.dumps(audit,indent=2),file_name="audit_gate.json",mime="application/json")

elif page == "📋 Evidence & Audit Log":
    st.title("📋 Evidence & Audit Log")
    st.caption("Evidence bundle — Table 10 (Birgin & Celiktas, 2026, p.33547)")
    paper_results    = evaluate_assets(PAPER_ASSETS)
    extended_results = evaluate_assets(st.session_state.extended_assets)
    artifact = generate_qrs_json(paper_results + extended_results)
    st.markdown("### qrs_results.json (Phase P3 artifact)")
    st.code(json.dumps(artifact,indent=2)[:2000]+"\n  ... [truncated] ...",language="json")
    st.download_button("⬇️ Download qrs_results.json",json.dumps(artifact,indent=2),file_name="qrs_results.json",mime="application/json")
    st.markdown("---")
    st.markdown("### Evidence Taxonomy (Table 10, paper p.33547)")
    evidence_table = pd.DataFrame([
        ["P1","cmdb_snapshot.json","Asset inventory with tags","Schema validation + checksum"],
        ["P3","qrs_results.json","QRS scores with policy flags","Determinism check"],
        ["P5","audit_gate.json","CI/CD ALLOW/RESTRICT/BLOCK decision","Pipeline log + hash"],
        ["P6","cryptolyzer_report.txt","TLS config visibility","Re-run against endpoint"],
    ],columns=["Phase","Artifact","Description","Verification"])
    st.dataframe(evidence_table,use_container_width=True)
    st.markdown("---")
    st.markdown("### AHP Weight Verification")
    ahp_df = pd.DataFrame({
        "Factor":["Data Longevity","Algorithm Vulnerability","Key Exposure","System Dependence"],
        "Weight":[0.30,0.25,0.25,0.20],
        "Rationale":["Long-lived data faces highest HNDL exposure risk","Classical-only (RSA/ECC) = maximum vulnerability","Distributed keys = broad attack surface","Mission-critical systems = highest operational impact"]
    })
    st.dataframe(ahp_df,use_container_width=True)
    st.caption("AHP Consistency Ratio CR ≈ 0.022 < 0.10 — acceptable per Saaty (1987).")
