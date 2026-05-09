"""
Generic LLM client.

Provider-agnostic wrapper around any OpenAI-compatible chat completion API.
Configure via environment variables — see .env.example.
"""

import os
import requests
from typing import List, Dict


class LLMClient:

    def __init__(
        self,
        api_key: str = None,
        api_url: str = None,
        model: str = None,
        timeout: int = 30,
    ):
        self.api_key = api_key or os.environ["LLM_API_KEY"]
        self.api_url = api_url.rstrip("/") if api_url else os.environ["LLM_API_URL"].rstrip("/")
        self.model = model or os.environ["LLM_MODEL"]
        self.timeout = timeout

    def chat(self, messages: List[Dict]) -> str:
        """
        Send messages to the LLM API and return the response text.
        Raises requests.HTTPError on non-2xx responses.
        """
        response = requests.post(
            f"{self.api_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": messages,
                "max_tokens": 1024,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]