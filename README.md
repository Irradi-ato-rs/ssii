# VoidMetric (Open-Framework Core)

VoidMetric is a novel dual-math risk orchestration paradigm designed to deconstruct "Compliance Theater" (the watermelon metric effect, where an infrastructure posture appears green and compliant on paper while harboring fatal operational exploits). 

This repository houses the public open-core architecture, built natively using **Astro**, **Tailwind CSS**, and optimized for zero-cold-start execution inside serverless **Cloudflare Pages** and **Cloudflare Workers** environments.

## 1. Architectural Matrix Fabric

VoidMetric operationalizes [Systemic Integrity Axiomatic 4 and Enablers 3](https://irradi.ato.rs/p/systemic-integrity-axiomatic-enablers.html). It maps corporate risk as a static 4 × 3 continuous matrix crossing four **Axiomatic Domains (I)** against three **Systemic Enablers (J)**:

| Axiomatic Domain (i) | Structures (j=0) | Contents (j=1) | Facilities (j=2) |
| :--- | :--- | :--- | :--- |
| **1. Function** | Architecture / Policy | Logic / Source Code | Cloud Environments |
| **2. Features** | RBAC / Identity Gov | Crypto Parameters | API Gateways |
| **3. Elements** | Configurations / Secrets | Data Assets / Payload | Storage Buckets |
| **4. Execution** | Runtime Environments | Log / Telemetry Pipelines| Compute Infrastructure |

Input metrics are continuously streamed via automated edge scripts and normalized such that \(C_{i,j} \in [0.0, 1.0]\).

---

## 2. The Dual-Engine Core Mathematics

### Metric A: Continuous Maturity Matrix (Additive)
Tracks cumulative administrative effort, organizational spend, and checkmark compliance over time via double-summation:
'''math
$$\text{Score}_A = \frac{1}{4} \sum_{i=1}^{4} \sum_{j=1}^{3} (C_{i,j} \times w_j)$$
'''

### Metric B: The Operational Blueprint (Multiplicative)
An uncompromising series system that enforces the **Zero Property** (Risk Switch). Individual row verification vectors are aggregated via a weighted geometric product to prevent high compliance boundaries from masking critical vulnerabilities:
'''math
$$V_i = \prod_{j=1}^{3} (C_{i,j})^{w_j}$$
$$\text{SI}_{\text{Live}} = \prod_{i=1}^{4} V_i = \prod_{i=1}^{4} \prod_{j=1}^{3} (C_{i,j})^{w_j}$$
'''

> **Theorem 1 (The Zero Property):** If $\exists (k,m)$ such that $C_{k,m} = 0.0$, then $\text{SI}_{\text{Live}} = 0.0$. A single critical vulnerability completely collapses the operational integrity index, acting as a deterministic system circuit-breaker.

---

## 3. Project File Directory Matrix

```text
├── .github/workflows/    <-- CI Automation pipeline validations
├── src/
│   ├── components/
│   │   └── Footer.astro  <-- Shared minimalist footer component module
│   ├── layouts/
│   │   └── BaseLayout.astro
│   └── pages/
│       ├── api/v1/
│       │   └── compute.ts <-- Core headless V1 serverless math endpoint
│       ├── architecture.astro   <-- Brutalist open system blueprint
│       ├── index.astro          <-- Typography-driven interactive home node
│       ├── integrity-portal.astro <-- Continuous monitoring portal & audio klaxons
│       └── register.astro       <-- Multi-solution dynamic registration board
├── astro.config.mjs       <-- Cloudflare Serverless configuration adaptations
└── wrangler.toml          <-- Cloudflare Worker infrastructure mappings
```

---

## 4. API Endpoints & Verification

### Ingestion Validation Interface (`POST /api/v1/compute`)
Accepts a raw JSON numerical matrix array payload and returns parallel compliance/integrity metrics outputs.

#### Sandbox Evaluation via cURL:
```bash
curl -X POST https://fzoirm.com \
  -H "Content-Type: application/json" \
  -d '{"matrix": [[0.95,0.9,0.95],[0.9,0.95,0.9],[0.95,0.9,0.0],[0.9,0.9,0.95]]}'
```

#### Core Output Blueprint:
```json
{
  "metric_a_compliance": 0.8438,
  "metric_b_integrity": 0.0000,
  "row_validations": [0.9331, 0.9164, 0.0000, 0.9167],
  "status": "CRITICAL_RISK_SWITCH_TRIGGERED"
}
```

---

## 5. Security & Operational Boundaries

This public framework handles **anonymous, normalized metrics grids only**. 

For enterprise and sovereign customers connecting active logging environments (**Tenable, Microsoft Sentinel, CrowdStrike, AWS CloudTrail**), data ingestion, string parsers, normalization functions ($f_{\text{norm}}$), and custom SLA definitions are handled inside separate, private repositories and isolated processing workers. This guarantees that your enterprise log configurations and connection maps are completely hidden while ensuring runtime transparency.
