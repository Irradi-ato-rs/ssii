# VoidMetric (Extensible & On-Demand Core)

VoidMetric is a dual-math risk orchestration approach designed to close the gap between reported compliance and actual operational integrity — cases where a technological posture appears compliant on paper while harboring fatal operational exploits (the "watermelon metric effect"). It pairs an additive compliance metric with a multiplicative weakest-link metric side-by-side, using the gap between them as the primary diagnostic signal — surfaced through a 4×3 axiomatic/enabler matrix taxonomy.

This GitHub [public repository](https://github.com/Irradi-ato-rs/ssii) houses not only the open-core architecture but every artifact that powers VoidMetric except for a few proprietary dynamics, built natively using **Astro**, **Tailwind CSS** and optimized for zero-cold-start execution inside serverless **Cloudflare Workers** environments.

## 1. Architectural Matrix Fabric

[VoidMetric](https://ssii.fzoirm.com) operationalizes [Systemic Integrity Axiomatic 4 and Enablers 3](https://irradi.ato.rs/p/systemic-integrity-axiomatic-enablers.html), which serves as a cognitive catalyst in consulting engagements, aligning every stakeholder without requiring them to possess the formal notation to understand business system capabilities while uncovering value creators. It maps corporate (strategic velocity) governance system, security intelligence and risk mitigation as a static 4 × 3 continuous matrix crossing four **Axiomatic Domains (I)** against three **Technical Enablers (J)**:

| Axiomatic Domain (i) | Structures (j=0)         | Contents (j=1)            | Facilities (j=2)       |
| --------------------- | ------------------------ | -------------------------- | ------------------------ |
| **1. Function**       | Architecture / Policy    | Logic / Source Code        | Cloud Environments       |
| **2. Features**       | RBAC / Identity Gov      | Crypto Parameters           | API Gateways             |
| **3. Elements**       | Configurations / Secrets | Data Assets / Payload       | Storage Buckets          |
| **4. Execution**      | Runtime Environments     | Log / Telemetry Pipelines   | Compute Infrastructure   |

Formula indices are 0-based; table labels are 1-based for readability.

Input metrics are continuously streamed via automated edge scripts and normalized such that $C_{i,j} \in [0.0, 1.0]$.

---

## 2. The Dual-Math

### Metric A: Strategic Posture (Additive)

Tracks the organization's compliance posture as a context-weighted level, and its rate of change as a frozen-weight velocity.

**Level:**

$$
\text{Score}_A(t) = \sum_{i=0}^{3}\sum_{j=0}^{2} C_{i,j}(t)\cdot w_j(\vec{t})\cdot \alpha_i
$$

**Velocity (frozen-weight delta):**

$$
\Delta\text{Score}_A(t) = \text{Score}_A\bigl(t;\; w(\vec{t}-\Delta t)\bigr) - \text{Score}_A\bigl(t-\Delta t;\; w(\vec{t}-\Delta t)\bigr)
$$

Both computed on the same 4 × 3 matrix, same weights, same $\alpha$. $\Delta t$ = one scoring cycle. Input signal: raw $C_{i,j} \in [0,1]$ pre-decay.

where $w_j(\vec{t})$ are enabler weights dynamically re-allocated in proportion to a live threat-intelligence vector $\vec{t}$, and $\alpha_i$ is each axiomatic domain's fixed priority coefficient ($\sum_i \alpha_i = 1$).

$\Delta\text{Score}_A > 0$: improving. $\Delta\text{Score}_A < 0$: degrading. $\Delta\text{Score}_A \approx 0$: steady (ambiguous without Metric B context).

---

### Metric B: The Operational Blueprint (Multiplicative Core, Spectral-Adjusted)

An uncompromising series system built around a Risk Switch: row verification vectors are aggregated via a weighted geometric product per row, then combined harmonically across rows so that any single collapsed row dominates the aggregate rather than being diluted by strong rows elsewhere.

$$
V_i = \prod_{j=0}^{2} \bigl(C_{i,j}\bigr)^{w_j}
$$

$$
SI_{\text{raw}} = \left(\sum_{i=0}^{3} \alpha_i \, V_i^{-1}\right)^{-1}
$$

Each $C_{i,j}$ is itself derived from raw telemetry through a temporal decay function (older, unrefreshed signals drift toward zero confidence) and a sigmoid confidence transform before entering the matrix.

$SI_{\text{raw}}$ is further adjusted by a spectral chaos penalty, derived from the principal eigenvalue of the domain-covariance matrix, which detects correlated multi-domain degradation that a naive per-cell view would miss:

$$
\text{ChaosPenalty} = \kappa\,\max\!\Bigl(0,\;\lambda_{\max}(C) - \frac{\text{trace}(C)}{n}\Bigr), \quad \kappa = 0.25
$$

where $C$ is the domain-covariance matrix and $n$ is the number of domains.

$$
SI_{\text{Live}} = \max\!\bigl(0.0001,\; SI_{\text{raw}} - \text{ChaosPenalty}\bigr)
$$

**Guarantee 1 (The Risk Switch):** If any individual verification signal's confidence falls below a critical threshold (currently $< 0.05$), the breaker trips and $SI_{\text{Live}}$ is capped at a near-zero floor (currently $0.015$) regardless of every other signal's value. A single critical vulnerability cannot be diluted by high scores elsewhere in the matrix.   

---

## Diagnostics

**Watermelon Index (Primary Diagnostic)**

A deception detector that measures the divergence between administrative compliance and operational integrity. It peaks when the rind is green and the flesh is red — the case where checkmark compliance is masking a collapsed operational blueprint. It is zero when the two metrics agree in either direction.

$$
\boxed{\text{WI}(t) = \text{Score}_A(t)\cdot\bigl(1 - SI_{\text{Live}}(t)\bigr)}
$$

WI is intentionally one-sided. It is a deception detector, not a severity ranker. The honest-failure case (both metrics low) is not deceptive — it is visible in the constituent metrics and caught by the Risk Switch. Flagging it here would dilute the diagnostic's purpose.

Under the Risk Switch floor ($SI_{\text{Live}} \approx 0.015$), $1 - SI_{\text{Live}} \approx 1$, so $\text{WI} \approx \text{Score}_A$. The diagnostic passes through rather than collapsing.

**Honest Failure Index (Companion Diagnostic)**

The companion to the Watermelon Index. Where WI detects deception (compliance high, integrity low), HF detects honest failure (both low, visible, not masked). Together they tile the degraded space: any point where $SI_{\text{Live}} < 1$ is either watermelon or honest failure, never both.

$$
\boxed{\text{HF}(t) = \bigl(1 - \text{Score}_A(t)\bigr)\cdot\bigl(1 - SI_{\text{Live}}(t)\bigr)}
$$

**Identity 1 (Complementary Tiling):** For all $t$,

$$
\text{WI}(t) + \text{HF}(t) = 1 - SI_{\text{Live}}(t)
$$

This identity provides a free check for unit testing: assert $\left|\text{WI} + \text{HF} - (1 - SI_{\text{Live}})\right| < \varepsilon$ on every cycle.

HF is not a substitute for reading Score_A and SI_Live individually. It is a convenience aggregate for the consulting narrative — the number that answers "how bad is it, honestly?" when the answer is "bad, and no one is being fooled by it."

---

## Joint Reading

| WI | HF | Diagnosis |
|:---:|:---:|---|
| High | Low | Watermelon — compliance masking failure |
| Low | High | Honest failure — both degraded, visible |
| Low | Low | Healthy — aligned |

---

## 3. Governance System & Capabilities Blueprint — Project File Directory

```
├── .github/workflows/          <-- CI Automation pipeline validations // planned
├── src/
│   ├── components/
│   │   └── Footer.astro
│   ├── config/
│   │   └── tenants.ts          <-- Generic, auditable KV lookup logic. Actual tenant records
│   │                               (domains, tenant IDs, endpoints) are never committed here —
│   │                               they live in the private VM_TENANT_DIRECTORY KV namespace.
│   ├── layouts/
│   │   └── BaseLayout.astro
│   ├── lib/
│   │   └── scoring-engine.ts   <-- Pure computation. No I/O, no side effects, zero-persistence.
│   │                               Liftable into a separate authoritative Worker unchanged.
│   ├── middleware.ts            <-- Session verification, role resolution (VoidMetric-controlled allow-list only)
│   └── pages/
│       ├── api/
│       │   ├── register.ts      <-- OIDC handshake initiation (PKCE + nonce)
│       │   └── auth/
│       │       ├── callback.ts  <-- Token exchange, JWT verification
│       │       └── signout.ts   <-- RP-Initiated Logout
│       ├── architecture.astro
│       ├── index.astro
│       ├── integrity-portal.astro
│       └── login.astro
├── workers/
│   └── ssii-consumer.ts        <-- Queue consumer. Zero-persistence: pure compute + structured log.
│                                   No KV, no D1, no Durable Objects. Results are ephemeral.
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

## 4. Compute Pipeline & Output Schema

Computation runs asynchronously via a Cloudflare Queue. The consumer receives a pre-normalized, blinded 12-node telemetry stream, executes the scoring engine in memory, and emits a structured log. **No metric data is persisted** — no KV, no D1, no Durable Objects. Results exist only in the log stream.

### Queue message shape:

```json
{
  "type": "signal_update",
  "tenantId": "acme-corp",
  "paddedStream": [
    { "maskedValue": 0.95, "row": 0, "col": 0, "lastTelemetryHeartbeat": 1754899200 }
  ],
  "threatIntelVector": [0.0, 0.0, 0.0],
  "timestamp": 1754899200
}
```

### Structured log output (per message):

```json
{
  "metric_a_compliance": 0.8438,
  "metric_b_integrity": 0.0150,
  "status": "CRITICAL_RISK_SWITCH_TRIGGERED",
  "watermelon_index": 0.8288,
  "honest_failure_index": 0.0150,
  "row_validations": [0.9331, 0.9164, 0.0000, 0.9167],
  "spectral_analysis": {
    "chaos_index_penalty": 0.03211,
    "principal_eigenvalue": 1.20441,
    "resonance_exploit_chain_detected": false
  }
}
```

---

## 5. Security & Operational Boundaries

The compute pipeline processes **pre-normalized, blinded telemetry nodes only** — it never receives a raw SIEM finding or credential directly.

### Compliance Isolation of Identity and Ingestion

- **Isolated Service Processing Units**: For enterprise and sovereign customers connecting active identity providers (Okta, Microsoft Entra ID, Ping Identity) alongside security intelligence APIs and active logging environments (Tenable, Microsoft Sentinel, CrowdStrike, AWS CloudTrail):

Data ingestion, identity token exchange, string parsers, normalization functions ($f_{norm}$), and custom SLA definitions are handled entirely inside separate, secured, and isolated service processing units — including but not limited to private repositories and serverless compute.

Tenant identity records (domains, Azure/Okta/Ping tenant IDs, IdP endpoints) are stored exclusively in a private Cloudflare KV namespace, populated out-of-band during customer onboarding, and are never committed to this public repository. The lookup logic that queries this data is open for audit; the records it queries are not.

Engineered as a **Stateless, Zero-Persistence, Edge-Native, Non-Linear Operational Validation Engine**, the compute pipeline itself processes telemetry in real-time fluid memory without writing metric data to disk. A narrow, explicitly-scoped exception exists for tenant onboarding-status tracking — a small key-value store holding only onboarding-completion flags and invite lists per tenant domain. This is control-plane bookkeeping, not telemetry storage, and holds no metric values, raw signals, or credentials.

This guarantees that your enterprise credentials — SIEM/webhook tokens, IdP client secrets, tenant identity records, and platform role assignments — never enter the public codebase and are isolated within private, non-public runtime data stores and service boundaries, while the compute engine's own math, the federation protocol logic, and the role-based access model remain fully open for audit.

*(A stronger, cryptographic-at-rest guarantee for this isolated data is a planned follow-up, not yet implemented — this document will be updated when that lands.)*
