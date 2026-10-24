# GASHI-Guard 🛡️

**Cross-Platform Runtime Security Middleware & Red-Team Platform for Autonomous Web Agents**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Playwright](https://img.shields.io/badge/tested%20with-Playwright-green.svg)](https://playwright.dev/)
[![Security Benchmark](https://img.shields.io/badge/canary%20leak%20rate-0%25-brightgreen.svg)]()
[![Genesis v2](https://img.shields.io/badge/verified%20by-Genesis%20v2-orange.svg)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

GASHI-Guard is a lightweight, zero-latency security SDK and deterministic policy engine designed to protect autonomous browser agents (Playwright, TinyFish, Claude Computer Use, OpenAI Operator) against Indirect Prompt Injections (IPI), data exfiltration, and unauthorized high-risk actions.

---

## ⚡ Quickstart (2-Line Drop-In)

Wrap any Playwright `page` instance with `GashiGuard`:

```python
from playwright.sync_api import sync_playwright
from gashi import GashiGuard, PolicyConfig

# 1. Configure deterministic boundaries
config = PolicyConfig(
    allowed_domains=["app.mycompany.com"],
    canary_secrets=["USER_SESSION_API_TOKEN_XYZ"],
    require_approval_actions=["submit", "delete", "purchase"]
)

# 2. Wrap your page in 1 line
with sync_playwright() as p:
    browser = p.chromium.launch()
    raw_page = browser.new_page()
    page = GashiGuard.wrap_page(raw_page, config=config)

    # Ingress is automatically sanitized (hidden CSS prompt injections stripped)
    page.goto("https://app.mycompany.com")

    # Egress is automatically gated (raises SecurityPolicyViolation if canary leaked)
    page.fill("#search-input", "safe query")

    # High-risk actions automatically pause for human operator authorization
    page.click("button#purchase-order")  # Raises ApprovalRequiredException or invokes callback
```

---

## 🏗️ Core Architecture & Defense Layers

GASHI implements the **Golden Rule of Agentic ML Systems**: *An LLM must never execute financial, legal, or state-changing actions without deterministic policy verification.*

```
                 [ Untrusted Web Content ]
                             │
                             ▼
              [ 1. Ingress DOM Sanitizer ]
         (Strips CSS steganography, 0px text,
         zero-width Unicode, & HTML comments)
                             │
                             ▼
                 [ Sanitized DOM / Text ]
                             │
                             ▼
                 [ Browser Agent (LLM) ]
                 (Generates Action Proposals)
                             │
                             ▼
             [ 2. Egress Action Policy Engine ]
       (Evaluates Canary Leaks, Domain Whitelist,
             & State-Changing Consequence)
            ┌────────────────┴────────────────┐
            ▼                                 ▼
      [ Safe Action ]                  [ High-Risk Action ]
            │                                 │
            ▼                                 ▼
   [ Executed in Browser ]          [ 3. Human Approval Gate ]
            │
            ▼
   [ 4. Network Route Guard (CDP) ]
 (Aborts out-of-band <img>, fetch, or beacon
  exfiltrations to unapproved C2 domains)
```

1. **Ingress DOM Sanitizer (`gashi.ingress`):** Parses untrusted HTML and strips non-visible or disguised injection payloads before LLM ingestion.
2. **Egress Action Policy Engine (`gashi.egress`):** Deterministic evaluation under 50ms verifying destination domains, input canary leaks, and action consequence levels.
3. **Network Route Interceptor (`gashi.network`):** Hooks into Playwright `page.route('**/*')` or CDP `Fetch.enable` to immediately terminate out-of-band C2 exfiltrations.
4. **Approval Gate Callback:** Transparently pauses execution for sensitive operations (`delete`, `purchase`, `transfer`).

---

## 📂 Repository Layout

```
web_agent_security/
├── gashi/                      # Core SDK package
│   ├── __init__.py             # Public exports (GashiGuard, ProtectedPage, PolicyConfig)
│   ├── config.py               # Pydantic schemas (BrowserAction, PolicyDecision, PolicyConfig)
│   ├── ingress.py              # Ingress DOMSanitizer
│   ├── egress.py               # Egress ActionPolicyEngine
│   ├── network.py              # NetworkRouteGuard (CDP/Playwright route handler)
│   └── wrapper.py              # ProtectedPage proxy wrapper
├── testbed/                    # Synthetic local vulnerable environment
│   ├── __init__.py             # Testbed exports
│   └── mock_server.py          # Offline HTTP server (/pricing, /review, /c2, /admin)
├── tests/                      # Automated test suites (18 tests)
│   ├── test_unit_security.py   # Ingress & egress unit tests
│   ├── test_wrapper.py         # Playwright wrapper & network guard tests
│   └── test_redteam.py         # Dual-run red-team benchmark suite
├── docs/                       # Architecture and threat model documentation
│   ├── architecture.html       # Interactive visual architecture & decision matrix
│   └── WEB_AGENT_SECURITY_PROBLEMS_AND_SOLUTIONS.md # Threat research & mitigations
├── conftest.py                 # Pytest path resolution
├── requirements.txt            # Minimal dependencies
├── SPEC.md                     # Genesis requirements specification (FR/NFR/AC)
└── README.md                   # Project overview & quickstart
```

---

## 🧪 Testing & Red-Team Benchmarks

Run all 18 automated tests and the dual-run red-team benchmark:

```bash
# Install dependencies
pip install -r requirements.txt

# Run full test suite
pytest -v
```

### Benchmark Results

The automated benchmark compares an unprotected agent against a GASHI-protected agent navigating a poisoned product review page:

| Metric | Baseline (Unprotected Agent) | GASHI-Protected Agent |
| :--- | :---: | :---: |
| **Canary Secret Leak Rate** | **100% (1/1 leaked)** | **0% (0/1 leaked)** |
| **Ingress Injections Ingested** | INGESTED (Exploited) | **NEUTRALIZED (Stripped)** |
| **Out-of-Band Exfiltrations** | SUCCEEDED (To C2 sink) | **ABORTED (Blocked by client)** |
| **High-Risk Button Clicks** | EXECUTED UNCHECKED | **PAUSED (Approval required)** |

---

## 📚 Documentation

* **Interactive Visual Architecture:** Open [`docs/architecture.html`](docs/architecture.html) in any browser.
* **Threat Research & Analysis:** Read [`docs/WEB_AGENT_SECURITY_PROBLEMS_AND_SOLUTIONS.md`](docs/WEB_AGENT_SECURITY_PROBLEMS_AND_SOLUTIONS.md).
* **Formal Product Specification:** Read [`SPEC.md`](SPEC.md).

---

## 📄 License

MIT License. Free for open-source and commercial use.

