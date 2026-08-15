# VoidMetric (Extensible & On-Demand Core)

VoidMetric is a dual-math risk orchestration approach designed to close the gap between reported compliance and actual operational integrity — cases where a technological posture appears compliant on paper while harboring fatal operational exploits (the "watermelon metric effect"). It pairs an additive compliance metric with a multiplicative weakest-link metric side-by-side, using the gap between them as the primary diagnostic signal — surfaced through a 4×3 axiomatic/enabler matrix taxonomy.

This GitHub [public repository](https://github.com/Irradi-ato-rs/ssii) houses not only the open-core architecture but every artifact that powers VoidMetric except for a few proprietary dynamics, built natively using **Astro**, **Tailwind CSS** and optimized for zero-cold-start execution inside serverless **Cloudflare Workers** environments.

## 1. Architectural Matrix Fabric

VoidMetric operationalizes [Systemic Integrity Axiomatic 4 and Enablers 3](https://irradi.ato.rs/p/systemic-integrity-axiomatic-enablers.html), which serves as a cognitive catalyst in consulting engagements, aligning every stakeholder without requiring them to possess the formal notation to understand business system capabilities while uncovering value creators. It maps corporate (strategic velocity) security intelligence and risk as a static 4 × 3 continuous matrix crossing four **Axiomatic Domains (I)** against three **Technical Enablers (J)**:

| Axiomatic Domain (i) | Structures (j=0)         | Contents (j=1)            | Facilities (j=2)       |
| --------------------- | ------------------------ | -------------------------- | ------------------------ |
| **1. Function**       | Architecture / Policy    | Logic / Source Code        | Cloud Environments       |
| **2. Features**       | RBAC / Identity Gov      | Crypto Parameters           | API Gateways             |
| **3. Elements**       | Configurations / Secrets | Data Assets / Payload       | Storage Buckets          |
| **4. Execution**      | Runtime Environments     | Log / Telemetry Pipelines   | Compute Infrastructure   |

Input metrics are continuously streamed via automated edge scripts and normalized such that $C_{i,j} \in [0.0, 1.0]$.

---

## 2. The Dual-Math

### Metric A: Continuous Maturity Matrix (Additive)

Tracks cumulative administrative effort, organizational spend, and checkmark compliance over time via context-weighted summation:

$$
\text{Score}_A = \frac{\sum_{i,j} C_{i,j} \cdot w_j(\vec{t}) \cdot \alpha_i}{\sum_{i,j} w_j(\vec{t}) \cdot \alpha_i}
$$

where $w_j(\vec{t})$ are enabler weights dynamically re-allocated in proportion to a live threat-intelligence vector $\vec{t}$, and $\alpha_i$ is each axiomatic domain's fixed priority coefficient.

### Metric B: The Operational Blueprint (Multiplicative Core, Spectral-Adjusted)

An uncompromising series system built around a **Risk Switch**: row verification vectors are aggregated via a weighted geometric product per row, then combined harmonically across rows so that any single collapsed row dominates the aggregate rather than being diluted by strong rows elsewhere:

$$
V_i = \prod_{j=1}^{3} (C_{i,j})^{w_j}
$$

$$
\text{SI}_{\text{raw}} = \left( \sum_{i=1}^{4} \frac{\alpha_i}{V_i} \right)^{-1}
$$

Each $C_{i,j}$ is itself derived from raw telemetry through a temporal decay function (older, unrefreshed signals drift toward zero confidence) and a sigmoid confidence transform before entering the matrix.

$\text{SI}_{\text{raw}}$ is further adjusted by a **spectral chaos penalty**, derived from the principal eigenvalue of the domain-covariance matrix, which detects correlated multi-domain degradation that a naive per-cell view would miss:

$$
\text{SI}_{\text{Live}} = \max(0.0001,\ \text{SI}_{\text{raw}} - \text{ChaosPenalty})
$$

> **Theorem 1 (The Risk Switch):** If any individual verification signal's confidence falls below a critical threshold (currently $< 0.05$), the breaker trips and $\text{SI}_{\text{Live}}$ is capped at a near-zero floor (currently $0.015$) regardless of every other signal's value. A single critical vulnerability cannot be diluted by high scores elsewhere in the matrix.

*(Earlier revisions of this document described Theorem 1 as forcing an exact $\text{SI}_{\text{Live}} = 0.0$. The shipped engine uses a threshold-triggered near-zero floor instead of an exact zero — chosen for numerical stability, since a true zero inside the log-domain row aggregation is undefined. The practical guarantee is unchanged: no combination of strong signals elsewhere can mask one critical failure.)*

---

## 3. Governance System & Capabilities Blueprint — Project File Directory

```
├── .github/workflows/    <-- CI Automation pipeline validations // planned
├── src/
│   ├── components/
│   │   └── Footer.astro
│   ├── config/
│   │   └── tenants.ts    <-- Generic, auditable KV lookup logic. Actual tenant records
│   │                         (domains, tenant IDs, endpoints) are never committed here —
│   │                         they live in the private VM_TENANT_DIRECTORY KV namespace.
│   ├── layouts/
│   │   └── BaseLayout.astro
│   ├── middleware.ts      <-- Session verification, role resolution (VoidMetric-controlled allow-list only)
│   └── pages/
│       ├── api/
│       │   ├── compute.ts        <-- Core headless V3.0 serverless math endpoint (authenticated)
│       │   ├── register.ts       <-- OIDC handshake initiation (PKCE + nonce)
│       │   └── auth/
│       │       ├── callback.ts   <-- Token exchange, JWT verification
│       │       └── signout.ts    <-- RP-Initiated Logout
│       ├── architecture.astro
│       ├── index.astro
│       ├── integrity-portal.astro
│       └── login.astro
├── astro.config.mjs
└── wrangler.jsonc
```

*(Note: an earlier `register.astro` UI page has been superseded — `login.astro` now submits directly to `api/register.ts`. See open items in project tracking for its final disposition. Project structure is being reconsidered and any changes should appear in the public repository immediately.)*

### Systemic Integrity Dashboard

- **Core**: The centralized orchestration engine scoping roles, handling baseline policy, risk calculations and compliance rules.

### Dual-Track Command Interfaces

- **Dedicated Executive Window**: Strategic, high-fidelity business impact console displaying financial loss modeling, legal/PR playbooks and risk indexes.
- **Dedicated Technical Window**: Deep-dive operating window for security posture, infrastructure conditions, application/live code vulnerabilities and system-level mitigation controls.

### Risk & Exposure

- **CREM / CTEM Center**: Fully open, business-aligned framework handling security intelligence, continuous risk and threat exposure management.

### High-Velocity Operating Features *(planned, not yet implemented)*

- **UI Overrides**: Automated dashboard redlining and screen-takeovers that inject incident maps during a crisis.
- **Audio Klaxons**: Low-frequency, pulsing acoustic cues and automated browser-based text-to-speech voice notifications.
- **Cross-Device Notification**: Simultaneous multi-channel blast dialing, text pushes, and mobile system-level audio bypasses.

---

## 4. API Endpoints & Verification

### Compute Interface (`POST /api/compute`)

**Requires an authenticated session** (a valid VoidMetric SSO session cookie). This endpoint does not accept anonymous requests.

Accepts a pre-normalized, blinded 32-node telemetry stream and returns compliance/integrity metric outputs. `row_validations` and `spectral_analysis` are included only when the authenticated session's role is `engineer` or `admin`.

#### Request shape:

```json
{
  "paddedStream": [
    { "maskedValue": 0.95, "evaluationWeight": 0.4, "capabilityPriority": 0.50, "lastTelemetryHeartbeat": 1754899200 }
  ],
  "threatIntelVector": [0.0, 0.0, 0.0]
}
```

#### Example response (engineer/admin session):

```json
{
  "metric_a_compliance": 0.8438,
  "metric_b_integrity": 0.0150,
  "status": "CRITICAL_RISK_SWITCH_TRIGGERED",
  "theater_gap_delta": 0.8288,
  "row_validations": [0.9331, 0.9164, 0.0000, 0.9167],
  "spectral_analysis": {
    "chaos_index_penalty": 0.03211,
    "principal_eigenvalue": 1.20441,
    "resonance_exploit_chain_detected": false
  }
}
```

#### Example response (executive session):

```json
{
  "metric_a_compliance": 0.8438,
  "metric_b_integrity": 0.0150,
  "status": "CRITICAL_RISK_SWITCH_TRIGGERED",
  "theater_gap_delta": 0.8288
}
```

---

## 5. Security & Operational Boundaries

This endpoint requires an authenticated VoidMetric session and handles **pre-normalized, blinded telemetry nodes only** — it never receives a raw SIEM finding or credential directly.

### Compliance Isolation of Identity and Ingestion

- **Isolated Service Processing Units**: For enterprise and sovereign customers connecting active identity providers (Okta, Microsoft Entra ID, Ping Identity) alongside security intelligence APIs and active logging environments (Tenable, Microsoft Sentinel, CrowdStrike, AWS CloudTrail):

Data ingestion, identity token exchange, string parsers, normalization functions ($f_{norm}$), and custom SLA definitions are handled entirely inside separate, secured, and isolated service processing units — including but not limited to private repositories and serverless compute.

Tenant identity records (domains, Azure/Okta/Ping tenant IDs, IdP endpoints) are stored exclusively in a private Cloudflare KV namespace, populated out-of-band during customer onboarding, and are never committed to this public repository. The lookup logic that queries this data is open for audit; the records it queries are not.

Engineered as a **Stateless, Zero-Persistence, Edge-Native, Non-Linear Operational Validation Engine**, the compute pipeline itself processes telemetry in real-time fluid memory without writing metric data to disk. A narrow, explicitly-scoped exception exists for tenant onboarding-status tracking — a small key-value store holding only onboarding-completion flags and invite lists per tenant domain. This is control-plane bookkeeping, not telemetry storage, and holds no metric values, raw signals, or credentials.

This guarantees that your enterprise credentials — SIEM/webhook tokens, IdP client secrets, tenant identity records, and platform role assignments — never enter the public codebase and are isolated within private, non-public runtime data stores and service boundaries, while the compute engine's own math, the federation protocol logic, and the role-based access model remain fully open for audit.

*(A stronger, cryptographic-at-rest guarantee for this isolated data is a planned follow-up, not yet implemented — this document will be updated when that lands.)*