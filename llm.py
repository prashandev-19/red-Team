"""Tiny client for any OpenAI-compatible chat API (Groq, Gemini, OpenAI, ...).
Settings come from the .env file next to this script."""
import os
import pathlib
import time

import requests


def _load_env():
    p = pathlib.Path(__file__).with_name(".env")
    if p.exists():
        raw = p.read_bytes()
        text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig")
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if not os.environ.get(k.strip()):
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")

_load_env()
URL = os.environ.get("LLM_API_URL", "https://api.groq.com/openai/v1").rstrip("/")
KEY = os.environ.get("LLM_API_KEY", "")
MODEL = os.environ.get("LLM_MODEL", "llama-3.1-8b-instant")
DELAY = float(os.environ.get("LLM_DELAY", "2"))      # pause between calls (free tiers have rate limits)


class LLMError(Exception):
    pass


def chat(system, user, temperature=0.7):
    """Send one system + user message to the model and return its reply text."""
    if not KEY:
        raise SystemExit("Set LLM_API_KEY in .env first (see Project3_Guide.md).")
    body = {"model": MODEL, "temperature": temperature, "max_tokens": 400,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    for attempt in range(5):
        r = requests.post(f"{URL}/chat/completions", json=body, timeout=60,
                          headers={"Authorization": "Bearer " + KEY})
        if r.status_code == 429:                       # rate limited: wait and retry
            time.sleep(min(float(r.headers.get("retry-after", 5 * (attempt + 1))), 60))
            continue
        if r.status_code != 200:
            raise LLMError(f"{r.status_code} {r.text[:200]}")
        time.sleep(DELAY)
        return (r.json()["choices"][0]["message"].get("content") or "").strip()
    raise LLMError("rate limited too many times")
