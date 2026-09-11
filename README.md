# 🔐 QuantumShield — PQC Transition Toolkit

**A working risk-scoring and CI/CD enforcement engine for organizations preparing for the post-quantum cryptography transition.**

Built on and extending: Birgin & Celiktas (2026). *"From Policy to Practice: A Sector-Agnostic Operational Framework for Post-Quantum Cryptography Transition."* IEEE Access, Vol. 14. DOI: [10.1109/ACCESS.2026.3669437](https://doi.org/10.1109/ACCESS.2026.3669437)

**By:** Muhammad Ahmad
**Course:** Information Security | University of Management and Technology, Lahore | Spring 2026

🔗 **Live demo:** (https://pqc-transition-toolkit-vejssahtbbtw47ydgvzvsb.streamlit.app/)

---

## What Is This?

Quantum computers capable of breaking RSA and ECC don't need to exist *yet* for today's encrypted data to be at risk — an attacker can harvest encrypted traffic now and decrypt it later once quantum computing catches up ("Harvest Now, Decrypt Later"). Organizations need a systematic way to figure out **which of their systems are most urgently exposed**, and enforce migration to quantum-resistant algorithms before it's too late.

This toolkit turns that problem into something concrete and interactive:

1. **Reproduces** the Quantum Risk Scoring (QRS) model from the referenced paper (Equation 1, Table 8)
2. **Lets you score real assets** through a live form — no pre-seeded fictional data, you enter what's real
3. **Simulates a CI/CD enforcement gate** (Algorithm 1 from the paper), returning `ALLOW` / `RESTRICT` / `BLOCK` decisions
4. **Generates downloadable audit artifacts** (`qrs_results.json`, `audit_gate.json`) so results are exportable, not just on-screen

---

## Try It

```bash
git clone https://github.com/<your-username>/quantumshield.git
cd quantumshield
pip install -r requirements.txt
streamlit run app.py
```

Opens at `http://localhost:8501`.

---

## How Scoring Works

```
QRS = (0.30 × Data Longevity)
    + (0.25 × Algorithm Vulnerability)
    + (0.25 × Key Exposure)
    + (0.20 × System Dependence)
```

Each factor is rated 1–10. Weights come from an AHP (Analytic Hierarchy Process) pairwise comparison in the source paper (Consistency Ratio = 0.022, well under the 0.10 acceptability threshold).

| Factor | Weight | Why it matters |
|---|---|---|
| Data Longevity | 0.30 | Data that must stay confidential for years is most exposed to harvest-now-decrypt-later attacks |
| Algorithm Vulnerability | 0.25 | Classical RSA/ECC offer zero resistance to a sufficiently powerful quantum computer |
| Key Exposure | 0.25 | Keys distributed across more systems/people mean a wider attack surface |
| System Dependence | 0.20 | Mission-critical systems carry the highest impact if compromised |

**Policy thresholds:**

| QRS Score | Policy | Meaning |
|---|---|---|
| ≥ 8.0 | 🔴 MIGRATE | Immediate PQC migration required |
| ≥ 7.0 | 🟠 HYBRID | Deploy hybrid classical + PQC controls |
| ≥ 6.0 | 🔵 MONITOR | Add telemetry, plan migration |
| < 6.0 | 🟢 DEFER | Low risk — reassess annually |

---

## What's In the App

- **Paper Assets dashboard** — exact reproduction of the 6 government-sector assets from the paper's Table 8, for validation against the published results
- **Extended QRS (your data)** — a live, session-based dataset you build yourself via the scoring form; supports Healthcare, Finance, Energy, Education, and custom sectors
- **CI/CD Enforcement Gate** — run either dataset through the gate logic and get an audit-ready ALLOW/RESTRICT/BLOCK decision with a downloadable JSON artifact
- **Evidence & Audit Log** — exports a combined `qrs_results.json` evidence bundle and shows the AHP weight rationale for review

---

## Project Structure

```
quantumshield/
├── app.py              # Streamlit dashboard — main entry point
├── qrs_engine.py        # QRS formula, CI/CD gate, standalone scoring module
├── requirements.txt
└── README.md
```

---

## Beyond the Original Paper

| Contribution | Description |
|---|---|
| Live custom scoring | The paper validates against 6 fixed government assets; this tool lets anyone score their own real assets interactively |
| Cross-sector support | Built-in sector tagging for Healthcare, Finance, Energy, and Education, not just Government |
| CI/CD gate simulation | The paper's enforcement algorithm, runnable live with instant ALLOW/RESTRICT/BLOCK feedback |
| Exportable evidence | One-click JSON artifact downloads for audit trails, matching the paper's evidence taxonomy (Table 10) |

---

## Reference

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
