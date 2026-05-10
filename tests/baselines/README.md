# Baseline Runners

Run each script in a **separate terminal** — do not run them together.
Each loads a large model (~700MB) and will OOM-kill if combined.

```bash
# 1. Presidio standalone
python tests/baselines/run_presidio_only.py

# 2. LLM Guard (DeBERTa-v3)
python tests/baselines/run_llmguard_only.py

# 3. Fintech LLM Guard (this project)
python tests/baselines/run_ours_only.py
```

Results saved to `evaluation/` as JSON.