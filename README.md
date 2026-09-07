# VoidMetric | Sovereign Systemic Integrity Intelligence (Extensible & On-Demand Core)

A dual-math risk orchestration approach that closes the gap between reported compliance and actual operational integrity — the "watermelon metric effect," where a posture appears green on paper while harboring fatal operational exploits.

> **What this is:** A governance instrument for *corporate board, CxOs, regulators and policy-makers*. The output is dispatch protocol for decision-makers, not a dashboard for engineers.
>
> **What it is not:** A monitoring tool. A SIEM. A compliance checklist. A replacement for your existing stack.
>
> **Technology alone feeds and processes data. It does not interpret:**

It pairs an **additive compliance metric** (Strategic Posture: context-weighted level + frozen-weight velocity) with a **multiplicative weakest-link metric** (Operational Blueprint: geometric-per-row, harmonic-across-rows, spectrally adjusted) over a shared 4×3 axiomatic/enabler matrix. The product of compliance and integrity deficit — not their difference — is the Watermelon Index, a one-sided deception detector that fires only when the rind is green and the flesh is red.

**The orchestration is in the output shape.** Every scoring cycle emits a structured decision vector, not a scalar:

| Field | Decides |
|---|---|
| `status` (NOMINAL / CRITICAL) | Severity tier, paging priority |
| `watermelon_index` = A × (1−S) | Route to compliance team (deception detected) |
| `honest_failure_index` = (1−A) × (1−S) | Route to ops team (visible failure, no deception) |
| `row_validations[4]` | Which domain to investigate first |
| `resonance_exploit_chain_detected` | Escalate to active threat-hunt |
| `velocity` (ΔScore_A) | Trajectory: intervene now or monitor |
| `temporal` (N>1) | Onset, persistence, trend, breaker history |
| `alpha_vector` | The α that produced this result (auditability) |
| `threat_intel_stale` (bool) | Weights are baseline, not live (24h fallback fired) |
| `threat_vector_anomaly` (bool) | Feed shifted abnormally between cycles (level/velocity divergence expected) |   

The math doesn't produce a number to look at. It produces a **dispatch protocol**: who gets paged, where they look first, whether to escalate, and whether the situation is worsening or stabilizing.

This GitHub [public repository](https://github.com/Irradi-ato-rs/ssii) houses not only the open-core architecture but every artifact that powers VoidMetric except for a few proprietary dynamics, built natively using **Astro**, **Tailwind CSS** and optimized for zero-cold-start execution inside serverless **Cloudflare Workers** environments.

---

## 1. Architectural Matrix Fabric

[VoidMetric](https://ssii.fzoirm.com) operationalizes [Systemic Integrity Axiomatic 4 and Enablers 3](https://irradi.ato.rs/p/systemic-integrity-axiomatic-enablers.html), which serves as a cognitive catalyst in consulting engagements, aligning every stakeholder without requiring them to possess the formal notation to understand business system capabilities while uncovering value creators. It maps corporate (strategic velocity) governance system, security intelligence and risk mitigation as a static 4 × 3 continuous matrix crossing four **Axiomatic Domains (I)** against three **Technical Enablers (J)**:

| Axiomatic Domain (i) | Structures (j=0)         | Contents (j=1)            | Facilities (j=2)       |
| --------------------- | ------------------------ | -------------------------- | ------------------------ |
| **1. Function**       | Architecture / Policy    | Logic / Source Code        | Cloud Environments       |
| **2. Features**       | RBAC / Identity          | Crypto Parameters           | API Gateways             |
| **3. Elements**       | Configurations / Secrets | Data Assets / Payload       | Storage Buckets          |
| **4. Execution**      | Runtime Environments     | Log / Telemetry Pipelines   | Compute Infrastructure   |

Formula indices are 0-based; table labels are 1-based for readability.

Input metrics are continuously streamed via automated edge scripts and normalized such that $C_{i,j} \in [0.0, 1.0]$.

---

## 2. The Dual-Math

### Metric A: Strategic Posture (Additive)

Tracks the organization's compliance posture as a context-weighted level, and its rate of change as a frozen-weight velocity.

**Level:**

$$Score_A(t) = \sum_{i=0}^{3} \sum_{j=0}^{2} C_{i,j}(t) \cdot w_j(\vec{t}) \cdot \alpha_i$$

**Velocity (frozen-weight delta):**

$$\Delta Score_A(t) = Score_A(t; w(\vec{t} - \Delta t)) - Score_A(t - \Delta t; w(\vec{t} - \Delta t))$$

Both computed on the same 4×3 matrix, same weights, same α. Δt = one scoring cycle. Input signal: raw $C_{i,j} \in [0, 1]$ pre-decay.

where $w_j(\vec{t})$ are enabler weights dynamically re-allocated in proportion to a live threat-intelligence vector $\vec{t}$, and $\alpha_i$ is each axiomatic domain's fixed priority coefficient ($\sum_i \alpha_i = 1$).

- $\Delta Score_A > 0$: improving
- $\Delta Score_A < 0$: degrading
- $\Delta Score_A \approx 0$: steady (ambiguous without Metric B context)

**Note:** $\Delta Score_A$ is a Laspeyres fixed-base index on raw signals, NOT the discrete derivative of $Score_A$. They answer different questions and cannot be cross-validated by integration. The tiling identity ($WI + HF = 1 - SI_{Live}$) is the only cross-metric invariant.

### Metric B: The Operational Blueprint (Multiplicative Core, Spectral-Adjusted)

An uncompromising series system built around a Risk Switch: row verification vectors are aggregated via a weighted geometric product per row, then combined harmonically across rows so that any single collapsed row dominates the aggregate rather than being diluted by strong rows elsewhere.

**Per-row geometric product:**

$$V_i = \prod_{j=0}^{2} (C_{i,j})^{w_j}$$

**Harmonic aggregation:**

$$SI_{raw} = \left( \sum_{i=0}^{3} \alpha_i \cdot V_i^{-1} \right)^{-1}$$

Each $C_{i,j}$ is itself derived from raw telemetry through a temporal decay function (older, unrefreshed signals drift toward zero confidence) and a sigmoid confidence transform before entering the matrix.

$SI_{raw}$ is further adjusted by a spectral chaos penalty (see below).

$$SI_{Live} = \max(0.0001,\; SI_{raw} - ChaosPenalty)$$

**Guarantee 1 (The Risk Switch):** If any individual verification signal's confidence falls below a critical threshold (currently < 0.05), the breaker trips and $SI_{Live}$ is capped at a near-zero floor (currently 0.015) regardless of every other signal's value. A single critical vulnerability cannot be diluted by high scores elsewhere in the matrix.

**Note:** The sigmoid cliff (k=10, x₀=0.5) and θ_breaker are co-located by construction, not by configuration. θ_breaker is derived from k and x₀ at commit time such that the breaker trips exactly where the sigmoid output equals the target floor. The co-location is a constraint enforced at commit, not a coincidence that holds for default parameters. Do not remove either; the system will not commit a configuration where they diverge.   

### Spectral Chaos Penalty (Deficit Gram Matrix)

The 4×4 Gram matrix is computed from the deficit vectors within a single snapshot:

$$G[i][q] = \sum_{j=0}^{2} (1 - C_{i,j}) \cdot (1 - C_{q,j})$$

The principal eigenvalue $\lambda_{max}(G)$ is estimated via power iteration (8 iterations, sufficient for 4×4). The penalty is:

$$ChaosPenalty = \max(0,\; (\lambda_{max}(G) - \text{trace}(G)/4) \times \kappa)$$

where $\kappa = 0.25$. This fires when multiple domains are simultaneously deficient in the same enabler columns — a correlated multi-domain failure mode invisible to per-cell inspection.

**Resonance flag:**

$$resonance\_exploit\_chain\_detected = (ChaosPenalty > 0.15)$$

A binary annotation: when the spectral penalty exceeds the resonance threshold, the system flags the pattern as a probable exploit chain.

**Note:** The Gram matrix measures concentration of absolute deficiency, not spread around a mean. Parallel deficit vectors (multiple domains weak in the same enabler) → rank-1 Gram → maximal penalty. Orthogonal deficits (each domain weak in a different enabler) → diagonal Gram → near-zero penalty. This is a concentration-of-deficiency detector, not a generic correlation detector.

**Why 4×4:** The 4th domain is what closes the structural evasion. With 3 domains (3 vectors in ℝ³), an attacker can place 3 mutually orthogonal deficit vectors and produce G = cI, zero penalty, zero detection. With 4 domains, that's geometrically impossible — you cannot place 4 mutually orthogonal vectors in ℝ³. The penalty has no structural blind spot.

### Diagnostics

**Watermelon Index (Primary Diagnostic)**

A deception detector that measures the divergence between administrative compliance and operational integrity. It peaks when the rind is green and the flesh is red — the case where checkmark compliance is masking a collapsed operational blueprint. It is zero when the two metrics agree in either direction.

$$WI(t) = Score_A(t) \cdot (1 - SI_{Live}(t))$$

WI is intentionally one-sided. It is a deception detector, not a severity ranker. The honest-failure case (both metrics low) is not deceptive — it is visible in the constituent metrics and caught by the Risk Switch. Flagging it here would dilute the diagnostic's purpose.

Under the Risk Switch floor ($SI_{Live} \approx 0.015$), $1 - SI_{Live} \approx 1$, so $WI \approx Score_A$. The diagnostic passes through rather than collapsing.

**Honest Failure Index (Companion Diagnostic)**

The companion to the Watermelon Index. Where WI detects deception (compliance high, integrity low), HF detects honest failure (both low, visible, not masked). Together they tile the degraded space: any point where $SI_{Live} < 1$ is either watermelon or honest failure, never both.

$$HF(t) = (1 - Score_A(t)) \cdot (1 - SI_{Live}(t))$$

**Identity 1 (Complementary Tiling):** For all $t$,

$$WI(t) + HF(t) = 1 - SI_{Live}(t)$$

This identity provides a free check for unit testing: assert $|WI + HF - (1 - SI_{Live})| < \varepsilon$ on every cycle.

HF is not a substitute for reading $Score_A$ and $SI_{Live}$ individually. It is a convenience aggregate for the consulting narrative — the number that answers "how bad is it, honestly?" when the answer is "bad, and no one is being fooled by it."

**Joint Reading:**

| WI | HF | Diagnosis |
|---|---|---|
| High | Low | Watermelon — compliance masking failure |
| Low | High | Honest failure — both degraded, visible |
| Low | Low | Healthy — integrity intact |

**Note:** The WI/HF boundary is at $Score_A = 0.5$, independent of $SI_{Live}$. The ratio $WI/HF = Score_A / (1 - Score_A)$, so the "which diagnostic is dominant" question reduces to a single threshold on one number.

### Status Determination

| Condition | Status |
|---|---|
| $SI_{Live} < 0.20$ | CRITICAL_RISK_SWITCH_TRIGGERED |
| $SI_{Live} \geq 0.20$ | NOMINAL |

The status threshold (0.20) is wider than the breaker threshold (0.05): a system can be flagged CRITICAL without any single cell tripping the breaker, if the aggregate integrity is sufficiently degraded.

**Note:** Only two states by design: the consulting narrative is binary ("are we critical or not?"). A third tier would dilute the decision. If you need granularity, read $SI_{Live}$ directly.      

---

## 3. Governance System & Capabilities Blueprint — Project File Directory

```
├── .github/workflows/          <-- CI Automation pipeline validations // planned
├── integrity-adapters/         <-- See note below
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
│   │   └── scoring-engine.ts       <-- Pure computation. No I/O, no side effects, zero-persistence.
│   │                                   Liftable into a separate authoritative Worker unchanged.
│   ├── middleware.ts               <-- Session verification, role resolution (VoidMetric-controlled allow-list only)
│   └── pages/
│       ├── api/
│       │   ├── register.ts         <-- OIDC handshake initiation (PKCE + nonce)
│       │   └── auth/
│       │       ├── callback.ts     <-- Token exchange, JWT verification
│       │       └── signout.ts      <-- RP-Initiated Logout
│       ├── architecture.astro
│       ├── index.astro
│       ├── integrity-portal.astro
│       └── login.astro
├── workers/
│   ├── ssii-consumer.ts            <-- Queue consumer. Zero-payload-persistence: pure compute + structured log.
│   │                                   No KV, no D1, no Durable Objects. Results are ephemeral.
│   │
│   └── dispatcher.ts               <-- Consumes posture change events / reads posture cache for context
│
├── astro.config.mjs
└── wrangler.jsonc
```
> `integrity-adapters/` — [Download here](https://github.com/Irradiators/integrity-adapters) for independent VoidMetric deployment or running only a specific open-source platform adapter.

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
