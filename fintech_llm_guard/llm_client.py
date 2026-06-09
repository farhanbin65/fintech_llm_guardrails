"""
Generic LLM client.
Provider-agnostic wrapper around any OpenAI-compatible chat completion API.
Configure via environment variables — see .env.example.

Quick start
-----------
from fintech_llm_guard import GuardrailPipeline, LLMClient

pipeline = GuardrailPipeline(
    api_key="your_key",
    api_url="https://your-provider/v1",
    model="your-model-name",
)

Advanced — bring your own client
---------------------------------
Implement LLMClientProtocol if you need custom auth, retries, or streaming:

    class MyClient:
        def chat(self, messages: list[dict]) -> str:
            ...

    pipeline = GuardrailPipeline(llm_client=MyClient())
"""

import os
import requests
from typing import List, Dict
from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMClientProtocol(Protocol):
    """
    Interface any LLM client must satisfy.
    Implement this if you want to bring your own client.

    Your client must have exactly one method:
        chat(messages: list[dict]) -> str

    messages format (OpenAI-compatible):
        [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user",   "content": "What is my balance?"},
        ]

    Return value:
        The model reply as a plain string.
    """
    def chat(self, messages: List[Dict]) -> str:
        ...


class LLMClient:
    """
    Built-in OpenAI-compatible client.
    Works with any provider that follows the OpenAI chat completions API:
    Groq, OpenAI, Together AI, Mistral, local Ollama, and others.

    Args:
        api_key:  Your provider API key.
                  Falls back to LLM_API_KEY environment variable.
        api_url:  Base URL of your provider, e.g.
                  https://api.groq.com/openai/v1
                  https://api.openai.com/v1
                  http://localhost:11434/v1  (Ollama)
                  Falls back to LLM_API_URL environment variable.
        model:    Model name, e.g. llama-3.3-70b-versatile, gpt-4o.
                  Falls back to LLM_MODEL environment variable.
        timeout:  Request timeout in seconds. Default 30.
    """
    def __init__(
        self,
        api_key: str = None,
        api_url: str = None,
        model: str = None,
        timeout: int = 30,
    ):
        self.api_key = api_key or os.environ["LLM_API_KEY"]
        self.api_url = (
            api_url.rstrip("/") if api_url
            else os.environ["LLM_API_URL"].rstrip("/")
        )
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
