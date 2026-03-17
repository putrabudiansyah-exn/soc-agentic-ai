"""core/llm_client.py — ChatOpenAI pointed at vLLM or Together.ai. Unchanged at migration."""
from __future__ import annotations
import os
from langchain_openai import ChatOpenAI


def get_llm(temperature: float = 0.1, max_tokens: int = 1200) -> ChatOpenAI:
    """
    Returns a ChatOpenAI client.
    Dev:     VLLM_BASE_URL=https://api.together.xyz/v1
    Staging: VLLM_BASE_URL=http://vllm-service:8000/v1
    No code change when switching — just update .env.
    """
    base_url = os.getenv("VLLM_BASE_URL", "https://api.together.xyz/v1")
    api_key  = os.getenv("VLLM_API_KEY",  "token")

    return ChatOpenAI(
        base_url    = base_url,
        api_key     = api_key,
        model       = "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        temperature = temperature,
        max_tokens  = max_tokens,
    )
