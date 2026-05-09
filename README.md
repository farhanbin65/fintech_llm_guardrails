# Fintech LLM Guardrails

A privacy-preserving and injection-resistant middleware layer for LLM-powered personal finance applications. Research project for GSAM 2026 (Ulster University).

## What this is

Personal finance chatbots send sensitive user data to third party LLM APIs and trust that data retrieved from their own database is safe. Both assumptions are wrong. This project implements and evaluates a four-layer middleware that:

1. Sanitises incoming user input against known prompt injection patterns
2. Structurally separates trusted instructions from untrusted data
3. Redacts PII before transmission to the LLM and remaps it in the response
4. Validates LLM output for unauthorised actions or data exfiltration

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

\`\`\`bash
git clone https://github.com/farhanbin65/fintech_llm_guard
cd fintech_llm_guard
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        
python -m app.routes
\`\`\`

## Architecture

See `docs/architecture.md` for the full diagram and threat model.

## Research

This work accompanies a paper submitted to the Global Symposium on Adaptive Manufacturing 2026 (GSAM). Pre-print and abstract will be linked here on acceptance.

## Author

Farhan Bin Hossain

## Licence

MIT — see LICENSE.