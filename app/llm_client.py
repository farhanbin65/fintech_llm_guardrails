"""
Generic LLM client.
Provider-agnostic wrapper around any OpenAI-compatible chat completion API.
"""

import os
import requests
from typing import List, Dict


class LLMClient:
    def __init__(self, api_key: str = None, api_url: str = None, model: str = None):
        self.api_key = api_key or os.environ["LLM_API_KEY"]
        self.api_url = api_url or os.environ["LLM_API_URL"]
        self.model = model or os.environ["LLM_MODEL"]

    def chat(self, messages: List[Dict]) -> str:
        response = requests.post(
            f"{self.api_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": messages,
            },
            timeout=30,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]