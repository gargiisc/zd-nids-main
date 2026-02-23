"""Firewall/NAC integration stubs for automated response actions."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class FirewallActionResult:
    success: bool
    provider: str
    target_ip: str
    action: str
    details: Dict


class FirewallIntegrator:
    """Vendor-agnostic firewall integration layer via REST APIs."""

    def __init__(self, provider: str, api_url: str, api_token: Optional[str] = None):
        self.provider = provider
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token

    def block_ip(self, ip_address: str, reason: str = "AI-NIDS automated block") -> FirewallActionResult:
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        payload = {"ip": ip_address, "reason": reason, "source": "ai-nids"}
        endpoint = f"{self.api_url}/block"

        try:
            response = requests.post(endpoint, json=payload, headers=headers, timeout=5)
            success = response.status_code < 300
            details = {"status_code": response.status_code, "response": response.text[:500]}
        except Exception as exc:
            logger.error("Firewall integration request failed: %s", exc)
            success = False
            details = {"error": str(exc)}

        return FirewallActionResult(
            success=success,
            provider=self.provider,
            target_ip=ip_address,
            action="block",
            details=details,
        )
