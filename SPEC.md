# Product specification — web_agent_security

> Status: draft. A coding agent must not implement product code until this specification is approved through Genesis.

## Problem

Autonomous web-browsing agents inherit the security risks of the open web. When an agent retrieves untrusted content (webpages, reviews, forum posts) that contains hidden or indirect prompt injections, the agent can be hijacked into performing unauthorized browser actions beyond user intent, such as exfiltrating canary secrets, leaking credentials, or executing premature form submissions. Existing browser agent frameworks lack deterministic policy gating, source provenance tracking, and verifiable red-team evaluation.

## Users

1. Security Engineers and Red-Teamers who need a measurable platform to evaluate browser agent vulnerabilities and defenses.
2. AI Agent Developers building autonomous browser tools who need deterministic guardrails to prevent excessive agency and data exfiltration.
3. Enterprise Security and Compliance Teams requiring auditable logs and human approval gates for sensitive actions.

## Functional requirements

- FR-1: The Content Gateway must inspect incoming web content and deterministically strip hidden DOM elements (display: none, visibility: hidden, zero-size font, HTML comments) before ingestion into the agent reasoning context.
- FR-2: The Content Gateway must detect canary tokens and known prompt injection signatures in retrieved web content and flag them as security events.
- FR-3: The Action Policy Engine must evaluate every structured browser action proposal (navigate, click, type, submit) against a configurable permission policy and classify it as ALLOW, BLOCK, or REQUIRE_APPROVAL.
- FR-4: The Action Policy Engine must block any outbound navigation, form submission, or network request that attempts to transmit protected canary data or reach unapproved destination domains.
- FR-5: The Browser Executor must execute only ALLOWed actions within an isolated Playwright browser instance, pausing on REQUIRE_APPROVAL actions until an explicit human decision is received.
- FR-6: The Red-Team Evaluation Harness must execute dual-run benchmarking comparing an unprotected Baseline agent against the GASHI-Protected agent on identical tasks and attack scenarios.
- FR-7: The system must stream real-time task progress, active browser state, and security monitoring events via Server-Sent Events (SSE).

## Non-functional requirements

- NFR-1: Security Decision Latency: The Action Policy Engine must evaluate action proposals in under 50 milliseconds to avoid degrading browser agent responsiveness.
- NFR-2: Exfiltration Prevention Rate: The policy engine must achieve a 100% block rate against canary secret exfiltration attempts in the defined red-team benchmark test suite.
- NFR-3: False Positive Rate: Benign browsing and legitimate form preparation tasks must achieve a 0% false-positive block rate on verified trusted domains.
- NFR-4: Auditability and Provenance: 100% of intercepted browser actions, security flags, and human approvals must be durably recorded in an SQLite audit log with timestamps, target URLs, and rule references.

## Constraints

- Runtime Environment: Python 3.10+ with FastAPI, Playwright for browser automation, and Pydantic for strict schema contracts.
- Model Independence: Security policy enforcement and content stripping must remain completely deterministic on the backend and never rely on the generative model to police itself.
- Platform: Must run on Windows/Linux local workstations with no external dependency requirements for core policy evaluation.

## Non-goals

- General-purpose CAPTCHA or Cloudflare bot-bypass solving.
- Fully autonomous financial transaction processing or multi-factor authentication handling without human intervention.
- Deep static analysis of compiled browser extensions or native OS binaries.

## Acceptance criteria

- AC-1: Running `pytest tests/test_redteam.py` confirms that in the baseline dual-run test, the unprotected agent leaks the canary token (attack success), while in the protected run, the GASHI policy engine blocks the exfiltration and reports 0% canary leak.
- AC-2: Running the benign workflow test confirms the agent successfully navigates, compares cloud providers, and fills the form with 0 false-positive blocks and stops at the human approval gate for final submission.
- AC-3: The FastAPI server exposes an SSE streaming endpoint `/api/stream/{task_id}` that emits valid JSON events for task progress, security alerts, and approval requests.

## Risks

- Evasion of Keyword Heuristics: Advanced semantic prompt injections may bypass basic regex filters. Mitigation: Layer deterministic DOM stripping, strict XML data encapsulation in prompt framing, and egress network filtering.
- Target DOM Instability: Public website redesigns may cause selector breakages. Mitigation: Provide a reproducible local testbed fixture for deterministic evaluation alongside live web scraping.

## Open questions

- None.
