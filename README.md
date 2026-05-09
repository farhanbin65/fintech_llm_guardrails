# Fintech LLM Guardrails

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-in%20development-orange.svg)
![Research](https://img.shields.io/badge/research-GSAM%202026-purple.svg)

A privacy-preserving and injection-resistant middleware layer for LLM-powered personal finance applications. Research project for GSAM 2026 (Ulster University London).

## What this is

Personal finance chatbots send sensitive user data to third-party LLM APIs and trust that data retrieved from their own database is safe. Both assumptions are wrong. This project implements and evaluates a four-layer middleware that:

1. Sanitises incoming user input against known prompt injection patterns
2. Structurally separates trusted instructions from untrusted data
3. Redacts PII before transmission to the LLM and re-maps it in the response
4. Validates LLM output for unauthorised actions or data exfiltration

The middleware is provider-agnostic and works with any LLM API that accepts OpenAI-compatible chat completion requests.

## Status

| Layer | Status |
|---|---|
| Input sanitiser | Planned |
| Structural separator | Planned |
| PII redactor | Planned |
| Output validator | Planned |
| Synthetic attack corpus | Planned |
| Evaluation harness | Planned |

## Quick start

```bash
git clone https://github.com/farhanbin65/fintech_llm_guard.git
cd fintech_llm_guard
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python -m app.routes
```

## Architecture

The middleware sits between the application backend and the LLM API. All sensitive data passes through it before leaving the trust boundary, and all responses pass back through it before reaching the user.

### System overview
![System architecture](docs/diagrams/system-architecture.svg)

### Defence stack
![Defence stack](docs/diagrams/defence-stack.svg)

### Threat model
![Threat model](docs/diagrams/threat-model.svg)

See [`docs/architecture.md`](docs/architecture.md%20) for a full written walkthrough of each layer and the threat model.

## Research

This work accompanies a paper submitted to the Global Symposium on Adaptive Manufacturing 2026 (GSAM). Pre-print and abstract will be linked here on acceptance.

## Author

Farhan Bin Hossain — Final-year Computing Systems student, Ulster University London.

## Licence

MIT — see [LICENSE](LICENSE).