# 🔐 PQC Transition Toolkit

**Implementing & Extending:** Birgin & Celiktas (2026). *"From Policy to Practice: A Sector-Agnostic Operational Framework for Post-Quantum Cryptography Transition."* IEEE Access, Vol. 14. DOI: [10.1109/ACCESS.2026.3669437](https://doi.org/10.1109/ACCESS.2026.3669437)

**By:** Muhammad Ahmad  
**Course:** Information Security | University of Management and Technology, Lahore | Spring 2026

---

## 📌 What This Tool Does

This toolkit operationalises the seven-phase PQC Transition Framework from the paper above into a working Python/Streamlit application. It:

1. **Reproduces** the Quantum Risk Scoring (QRS) model from the paper (Equation 1, Table 8)
2. **Extends** it with a 14-asset cross-sector dataset (Healthcare, Finance, Energy, Education) — **new contribution**
3. **Simulates** the CI/CD enforcement gate (Algorithm 1 from paper) with ALLOW/RESTRICT/BLOCK decisions
4. **Generates** verifiable audit artifacts (`qrs_results.json`, `audit_gate.json`)

---

## 🚀 Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/[your-username]/pqc-transition-toolkit.git
cd pqc-transition-toolkit

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the dashboard
streamlit run app.py
```

Open your browser at `http://localhost:8501`

---

## 🔢 QRS Formula (from paper, Equation 1)

```
QRS = (0.30 × Data Longevity) 
    + (0.25 × Algorithm Vulnerability)
    + (0.25 × Key Exposure)
    + (0.20 × System Dependence)
```

**AHP Weights** (paper Table 7, Consistency Ratio CR = 0.022 < 0.10):
| Factor | Weight | Rationale |
|--------|--------|-----------|
| Data Longevity | 0.30 | Long-lived data faces HNDL exposure |
| Algorithm Vulnerability | 0.25 | Classical RSA/ECC = max vulnerability |
| Key Exposure | 0.25 | Distributed keys = broad attack surface |
| System Dependence | 0.20 | Mission-critical = highest impact |

**Policy Thresholds** (paper Table 5):
| Score | Policy | Action |
|-------|--------|--------|
| ≥ 8.0 | 🔴 MIGRATE | Immediate PQC migration required |
| ≥ 7.0 | 🟠 HYBRID | Add hybrid classical+PQC controls |
| ≥ 6.0 | 🔵 MONITOR | Monitor, plan migration |
| < 6.0 | 🟢 DEFER | Low risk, reassess annually |

---

## 📁 Project Structure

```
pqc-transition-toolkit/
├── app.py                    # Streamlit dashboard entry point
├── requirements.txt
├── README.md
├── modules/
│   └── qrs_engine.py         # QRS formula, CI/CD gate, asset datasets
├── data/
│   └── extended_assets.json  # 14-asset cross-sector dataset (new contribution)
└── evidence/
    ├── qrs_results.json      # Phase P3 audit artifact
    └── audit_gate.json       # Phase P5 CI/CD enforcement artifact
```

---

## ✨ New Contributions (Beyond the Original Paper)

| Contribution | Description |
|---|---|
| Extended Dataset | 14 assets across 4 sectors vs original 6 assets (1 sector) |
| Sector Analysis | Average QRS per sector — Finance (8.73) and Energy (8.20) exceed MIGRATE threshold |
| Interactive Tool | Full web dashboard vs paper's static scenario |
| Custom Scoring | Users can score any asset in real time |
| CI/CD Simulation | Live gate decisions with downloadable audit artifacts |

---

## 📚 Reference

```bibtex
@article{birgin2026pqc,
  author  = {Birgin, Berat and Celiktas, Baris},
  title   = {From Policy to Practice: A Sector-Agnostic Operational Framework 
             for Post-Quantum Cryptography Transition},
  journal = {IEEE Access},
  volume  = {14},
  pages   = {33534--33551},
  year    = {2026},
  doi     = {10.1109/ACCESS.2026.3669437}
}
```
