# Architecture

This document describes the system architecture and the four-layer defence middleware at its core.

---

## System overview

<div align="center">
  <img src="diagrams/system-architecture.svg" width="580" alt="System architecture"/>
</div>

## Defence stack

<div align="center">
  <img src="diagrams/defence-stack.svg" width="580" alt="Defence stack"/>
</div>


### Layer 1 — Input sanitisation

Detects known prompt injection patterns in the incoming user message using regex and keyword matching. This is the first and fastest check — it catches low-effort, obvious attacks before anything else runs.

- **What it catches:** Direct injection attempts, role overrides, ChatML tokens, system prompt bypasses
- **What it misses:** Novel, obfuscated, or semantically disguised attacks
- **Implementation:** `middleware/sanitiser.py`

### Layer 2 — Structural separation

Wraps all untrusted data (transaction descriptions, imported CSV rows, MongoDB-retrieved content) in `<user_data>` delimiter tags before it is inserted into the LLM prompt. The system prompt explicitly instructs the model to treat anything inside those tags as data only, never as instructions.

- **What it catches:** Indirect injection via stored transaction descriptions, bank import files
- **What it misses:** Attacks that blend naturally into the surrounding prompt context
- **Implementation:** `middleware/separator.py`

### Layer 3 — PII redaction

The primary privacy contribution. Detects and pseudonymises personally identifiable information (PII) in the prompt before the outbound API call, then re-maps pseudonyms back to real values in the returned response. Uses Microsoft Presidio with custom financial entity recognisers.

Financial entities covered:
- Account numbers, sort codes, IBANs
- Card numbers
- National Insurance numbers
- Transaction IDs
- Named individuals in transaction descriptions

- **What it catches:** PII leakage to third-party LLM providers
- **What it misses:** PII embedded in deeply nested or encoded content
- **Implementation:** `middleware/redactor.py`

### Layer 4 — Output validation

Inspects the LLM response before it reaches the user. Rejects responses that contain unauthorised function calls, external URLs, or re-surfaced PII tokens that should have been redacted.

- **What it catches:** Action hijacking (vector 4), PII exfiltration via crafted response (vector 5)
- **What it misses:** Semantically harmful responses that pass syntactic checks
- **Implementation:** `middleware/output_validator.py`

### Layer 5 — Behavioural classifier (stretch goal)

A small DistilBERT classifier trained on labelled injection vs benign inputs. Provides a semantic defence layer that catches novel or obfuscated attacks that pattern-matching alone misses. Only attempted if Layers 1–4 ship by 1 July 2026.

---

## Threat model

The defence stack is designed around five attack vectors specific to LLM-powered personal finance applications. See [`threat-model.md`](threat-model.md) for the full breakdown.

<div align="center">
  <img src="diagrams/threat-model.svg" width="580" alt="Threat model"/>
</div>

| Vector | Description | Primary defence layer |
|---|---|---|
| 1. Direct chat injection | User crafts a message to override the system prompt | Layer 1 |
| 2. Transaction description injection | Malicious payload embedded in a stored merchant name or memo | Layer 2 |
| 3. Bank statement import injection | Payload hidden in an uploaded CSV field | Layer 2 |
| 4. Output-driven action hijacking | Injection triggers an unauthorised function call in the response | Layer 4 |
| 5. PII exfiltration via response | Injection causes the LLM to encode prior context into an external URL | Layers 3 + 4 |

---

## Pipeline orchestration

All layers are chained by `middleware/pipeline.py`, which is the single entry point called by Flask routes. Each layer can independently block a request and return an audit log entry. The pipeline fails closed — if any layer raises an unhandled exception, the request is blocked rather than passed through.

---

## Provider independence

The middleware does not depend on any specific LLM provider. The LLM client (`app/llm_client.py`) uses a generic OpenAI-compatible HTTP interface, configurable entirely through environment variables. See [`.env.example`](../.env.example) for configuration.

---

## Directory reference

```
middleware/
├── sanitiser.py          # Layer 1 — input sanitisation
├── separator.py          # Layer 2 — structural separation
├── redactor.py           # Layer 3 — PII redaction
├── output_validator.py   # Layer 4 — output validation
├── pipeline.py           # Orchestrator
app/
├── llm_client.py         # Generic OpenAI-compatible HTTP client
├── routes.py             # Flask endpoints
docs/
├── architecture.md       # This file
├── threat-model.md       # Full threat model with attack examples
diagrams/
├── system-architecture.svg
├── defence-stack.svg
└── threat-model.svg
```