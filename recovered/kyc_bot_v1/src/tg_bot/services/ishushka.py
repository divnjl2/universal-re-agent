"""
ISHUSHKA — AI chat integration via ishushka.com API.

Real endpoint from memory dump:
  https://api.ishushka.com/request

Config model from memory: gpt-5.1-chat
"""
from __future__ import annotations

import logging
from typing import Optional

import aiohttp

from tg_bot.config import config

logger = logging.getLogger(__name__)

# Real API URL from memory dump
ISHUSHKA_API_URL = "https://api.ishushka.com/request"


class IshushkaService:
    """
    AI chat completion service via ishushka.com.

    This is NOT OpenAI — it's a custom API wrapper at ishushka.com
    that proxies to various LLMs. Uses the /request endpoint.
    """

    def __init__(self) -> None:
        self.enabled: bool = config.ishushka.ENABLED
        self.api_key: str = config.ishushka.API_KEY or ""
        self.model: str = config.ishushka.MODEL  # "gpt-5.1-chat"
        self.system_prompt: str = config.ishushka.PROMPT or ""

    async def ask(
        self,
        user_message: str,
        conversation_history: Optional[list[dict[str, str]]] = None,
        max_tokens: int = 500,
    ) -> str:
        """
        Send a message to the ishushka API.

        Args:
            user_message: The user's question.
            conversation_history: Optional previous messages.
            max_tokens: Maximum response length.

        Returns:
            AI-generated response text.
        """
        if not self.enabled:
            return ""

        if not self.api_key:
            logger.warning("ISHUSHKA API key not configured.")
            return ""

        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        if conversation_history:
            messages.extend(conversation_history)
        messages.append({"role": "user", "content": user_message})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    ISHUSHKA_API_URL,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        logger.error("ISHUSHKA API error %d: %s", resp.status, error_text[:200])
                        return ""

                    data = await resp.json()
                    return (
                        data.get("choices", [{}])[0]
                        .get("message", {})
                        .get("content", "")
                    )
        except Exception as e:
            logger.exception("ISHUSHKA request failed: %s", e)
            return ""


# Singleton
ishushka = IshushkaService()
