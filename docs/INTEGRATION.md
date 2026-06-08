# Integration Guide

Fintech LLM Guardrails is a **sanitiser only** — it does not call any LLM itself.
Your application owns the LLM call. The pipeline handles everything before and after it.

```
User input
    ↓
pipeline.process_input()   ← sanitise + redact
    ↓
Your app calls LLM API     ← you control this
    ↓
pipeline.process_output()  ← validate + restore
    ↓
User sees safe response
```

---

## Installation

```bash
pip install fintech-llm-guard
```

---

## Initialisation

`GuardrailPipeline()` takes no arguments. It requires no API key and has
no dependency on any specific LLM provider.

```python
from fintech_llm_guard import GuardrailPipeline

pipeline = GuardrailPipeline()
```

> Always initialise outside your route function. spaCy loads its language
> model on first initialisation — this takes approximately 2 seconds.
> Initialising once at startup means every request after that runs at
> full speed. Initialising inside a route reloads spaCy on every request.

```python
# Correct — initialise once at startup
pipeline = GuardrailPipeline()

@app.route('/chat')
def chat():
    result = pipeline.process_input(...)

# Wrong — reloads spaCy on every request
@app.route('/chat')
def chat():
    pipeline = GuardrailPipeline()  # never do this
    result = pipeline.process_input(...)
```

---

## Step 1 — Process Input

```python
input_result = pipeline.process_input(
    user_message=user_message,        # str — raw user input
    transaction_context=transactions  # list of dicts — optional
)
```

### transaction_context format

```python
transactions = [
    {
        "date": "2026-06-01",
        "amount": -49.99,
        "merchant": "Tesco",
        "category": "groceries"
    },
    {
        "date": "2026-06-03",
        "amount": -12.50,
        "merchant": "TfL",
        "category": "transport"
    }
]
```

### input_result fields

| Field | Type | Present when | Description |
|---|---|---|---|
| `blocked` | bool | Always | True if request was blocked |
| `block_reason` | str | blocked = True | Which layer blocked it and why |
| `layer` | str | blocked = True | e.g. `"L1"`, `"L0b"` |
| `cleaned_prompt` | str | blocked = False | Sanitised and redacted prompt — send this to your LLM |
| `replacements` | dict | blocked = False | Placeholder to real value map — pass this to process_output |
| `risk_score` | float | blocked = False | L0b risk score between 0 and 1 |
| `pii_detected` | list | blocked = False | PII types found e.g. `["ACCOUNT", "CARD"]` |

---

## Step 2 — Call Your LLM

The pipeline plays no role here. Use whichever provider and library you prefer.

```python
if not input_result["blocked"]:
    llm_response = your_llm_client.chat(input_result["cleaned_prompt"])
```

Compatible with any provider:

```python
# LLM_API
from LLM_API import LLM_API
client = LLM_API(api_key=os.environ["LLM_API_KEY"])
response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": input_result["cleaned_prompt"]}]
)
llm_response = response.choices[0].message.content

# OpenAI
from openai import OpenAI
client = OpenAI(api_key=os.environ["LLM_API_KEY"])
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": input_result["cleaned_prompt"]}]
)
llm_response = response.choices[0].message.content

# Any OpenAI-compatible endpoint
client = OpenAI(
    api_key=os.environ["LLM_API_KEY"],
    base_url=os.environ["LLM_API_URL"]
)
```

---

## Step 3 — Process Output

```python
output_result = pipeline.process_output(
    llm_response=llm_response,
    replacements=input_result["replacements"]
)
```

### output_result fields

| Field | Type | Present when | Description |
|---|---|---|---|
| `blocked` | bool | Always | True if response was blocked |
| `block_reason` | str | blocked = True | Which layer blocked it and why |
| `layer` | str | blocked = True | e.g. `"L4a"`, `"L4b"` |
| `response` | str | blocked = False | Safe restored response — show this to the user |
| `restored` | bool | blocked = False | True if placeholders were successfully restored |

---

## Full Flask Example

```python
from flask import Flask, request, jsonify, session
from fintech_llm_guard import GuardrailPipeline
import os

app = Flask(__name__)

# Initialise once at startup
pipeline = GuardrailPipeline()

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message')
    user_id = session.get('user_id')

    # Fetch transactions from your database
    transactions = list(db.transactions.find(
        {"user_id": user_id},
        {"_id": 0, "date": 1, "amount": 1,
         "merchant": 1, "category": 1}
    ))

    # Step 1 — sanitise input
    input_result = pipeline.process_input(
        user_message=user_message,
        transaction_context=transactions
    )

    if input_result["blocked"]:
        return jsonify({
            "error": "Request blocked",
            "reason": input_result["block_reason"]
        }), 400

    # Step 2 — call your LLM
    llm_response = your_llm_client.chat(
        input_result["cleaned_prompt"]
    )

    # Step 3 — validate output
    output_result = pipeline.process_output(
        llm_response=llm_response,
        replacements=input_result["replacements"]
    )

    if output_result["blocked"]:
        return jsonify({
            "error": "Response blocked",
            "reason": output_result["block_reason"]
        }), 500

    return jsonify({
        "response": output_result["response"]
    })
```

---

## What Happens When Something is Blocked

The pipeline always returns immediately when a block is triggered.
Nothing proceeds to the next layer or to your LLM.

| Scenario | Layer | HTTP status to return |
|---|---|---|
| Suspicious request pattern | L0b | 400 |
| Prompt injection detected | L1 | 400 |
| High risk structural attack | L2 | 400 |
| PII found in LLM response | L4a | 500 |
| Unauthorised action attempt | L4b | 500 |
| Canary token triggered | Canary | 500 |

400 means the problem came from the user.
500 means the problem came from the LLM response.

---

## Common Questions

**Does the pipeline call the LLM?**
No. It sanitises input and validates output. Your application owns the LLM call.

**Which LLM providers does it support?**
All of them. The pipeline is provider-agnostic — Groq, OpenAI, Anthropic,
Azure OpenAI, or any OpenAI-compatible endpoint.

**Does it need a database?**
No. The replacement map lives in memory for the duration of one request only.
Nothing is persisted between requests.

**What happens if transaction_context is empty?**
The pipeline still runs all layers. Transaction context is optional — it
adds richer context for the structural separator but is not required.

**Why does process_output need the replacements dict?**
The LLM responds using placeholders like `[ACCOUNT_1]`. The replacements
dict is the map your pipeline created in process_input — it holds the
original real values so they can be restored in the response before
the user sees it.

**Can I use this outside of Flask?**
Yes. The pipeline is framework-agnostic. It works with Django, FastAPI,
or any plain Python script. The Flask example above shows the pattern —
adapt it to your framework.