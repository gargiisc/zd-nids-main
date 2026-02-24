"""Autonomous zero-day mitigation engine for Linux deployments."""

from __future__ import annotations

import ipaddress
import json
import logging
import shlex
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class MitigationEvent:
    """Event emitted for dashboard updates and audit."""

    attack_id: str
    attack_type: str
    source_ip: str
    severity: str
    action_taken: str
    status: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    rollback_available: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


class AttackTypeInference:
    """Behavior-based attack category inference for zero-day response."""

    def infer(self, flow: Dict[str, Any]) -> str:
        src_port = int(flow.get("src_port", 0) or 0)
        dst_port = int(flow.get("dst_port", 0) or 0)
        syn_count = int(flow.get("syn_count", 0) or 0)
        rst_count = int(flow.get("rst_count", 0) or 0)
        packets_per_second = float(flow.get("packets_per_second", 0.0) or 0.0)
        bytes_out = float(flow.get("bytes_sent", flow.get("bytes_forward", 0.0)) or 0.0)
        outbound_ratio = float(flow.get("outbound_ratio", 0.0) or 0.0)
        process_name = str(flow.get("process_name", "") or "").lower()
        command_line = str(flow.get("command_line", "") or "").lower()

        # Port scan behavior
        if syn_count > 30 and rst_count > 10:
            return "port_scan"

        # Reverse shell behavior
        if any(k in command_line for k in ["/bin/sh", "nc -e", "bash -i"]) or process_name in {"nc", "ncat"}:
            return "reverse_shell"

        # DDoS traffic spikes
        if packets_per_second >= 1000:
            return "ddos"

        # Suspicious outbound C2 communication
        if outbound_ratio > 0.85 and bytes_out > 500000:
            return "c2_communication"

        # Privilege escalation patterns
        if any(k in command_line for k in ["sudo su", "chmod +s", "setcap", "/etc/sudoers"]):
            return "privilege_escalation"

        # fallback heuristic from destination ports
        if dst_port in {22, 23, 3389} and src_port > 1024:
            return "suspicious_remote_access"

        return "unknown_zero_day"


class SafeLinuxResponder:
    """Executes mitigation actions with validation, allowlists, and rollback tracking."""

    def __init__(self, allowlist_ips: Optional[List[str]] = None, dry_run: bool = True):
        self.allowlist = set(allowlist_ips or [])
        self.dry_run = dry_run
        self.rollback_registry: Dict[str, List[List[str]]] = {}

    @staticmethod
    def _validate_ip(ip_value: str) -> str:
        ipaddress.ip_address(ip_value)
        return ip_value

    def _can_touch(self, ip_value: str) -> bool:
        return ip_value not in self.allowlist

    def _run(self, argv: List[str]) -> subprocess.CompletedProcess:
        if self.dry_run:
            return subprocess.CompletedProcess(argv, 0, stdout="dry_run", stderr="")
        return subprocess.run(argv, capture_output=True, text=True, check=False)

    def block_ip_iptables(self, attack_id: str, ip_value: str) -> Dict[str, Any]:
        ip_value = self._validate_ip(ip_value)
        if not self._can_touch(ip_value):
            return {"status": "skipped", "reason": "allowlisted_ip"}

        cmd = ["iptables", "-I", "INPUT", "-s", ip_value, "-j", "DROP"]
        rollback = ["iptables", "-D", "INPUT", "-s", ip_value, "-j", "DROP"]
        result = self._run(cmd)
        if result.returncode == 0:
            self.rollback_registry.setdefault(attack_id, []).append(rollback)
        return {"status": "success" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}

    def add_firewall_rule(self, attack_id: str, ip_value: str) -> Dict[str, Any]:
        return self.block_ip_iptables(attack_id=attack_id, ip_value=ip_value)

    def kill_suspicious_process(self, attack_id: str, pid: int) -> Dict[str, Any]:
        if pid <= 1:
            return {"status": "skipped", "reason": "unsafe_pid"}
        cmd = ["kill", "-9", str(pid)]
        result = self._run(cmd)
        return {"status": "success" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}

    def isolate_host(self, attack_id: str, interface: str = "eth0") -> Dict[str, Any]:
        iface = shlex.quote(interface)
        cmd = ["ip", "link", "set", iface, "down"]
        rollback = ["ip", "link", "set", iface, "up"]
        result = self._run(cmd)
        if result.returncode == 0:
            self.rollback_registry.setdefault(attack_id, []).append(rollback)
        return {"status": "success" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}

    def rate_limit_ip(self, attack_id: str, ip_value: str, limit_per_sec: int = 50) -> Dict[str, Any]:
        ip_value = self._validate_ip(ip_value)
        if not self._can_touch(ip_value):
            return {"status": "skipped", "reason": "allowlisted_ip"}

        cmd = [
            "iptables", "-I", "INPUT", "-s", ip_value,
            "-m", "limit", "--limit", f"{max(1, limit_per_sec)}/second", "-j", "ACCEPT",
        ]
        rollback = [
            "iptables", "-D", "INPUT", "-s", ip_value,
            "-m", "limit", "--limit", f"{max(1, limit_per_sec)}/second", "-j", "ACCEPT",
        ]
        result = self._run(cmd)
        if result.returncode == 0:
            self.rollback_registry.setdefault(attack_id, []).append(rollback)
        return {"status": "success" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}

    def write_blocklist(self, path: str, ip_value: str) -> Dict[str, Any]:
        ip_value = self._validate_ip(ip_value)
        block_path = Path(path)
        block_path.parent.mkdir(parents=True, exist_ok=True)
        with block_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{ip_value}\n")
        return {"status": "success", "path": str(block_path)}

    def rollback(self, attack_id: str) -> List[Dict[str, Any]]:
        rollback_commands = list(reversed(self.rollback_registry.get(attack_id, [])))
        outputs: List[Dict[str, Any]] = []
        for cmd in rollback_commands:
            result = self._run(cmd)
            outputs.append({"cmd": cmd, "status": "success" if result.returncode == 0 else "failed"})
        if attack_id in self.rollback_registry:
            del self.rollback_registry[attack_id]
        return outputs


class ZeroDayMitigationEngine:
    """Policy-driven autonomous mitigation with async detection hook support."""

    def __init__(
        self,
        policy_path: str = "config/mitigation_policies.yaml",
        confidence_threshold: float = 0.85,
        anomaly_threshold: float = 0.85,
        allowlist_ips: Optional[List[str]] = None,
        dry_run: bool = True,
        action_logger: Optional[Callable[[MitigationEvent], None]] = None,
        intel_share_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        threat_intel_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.policy_path = policy_path
        self.confidence_threshold = confidence_threshold
        self.anomaly_threshold = anomaly_threshold
        self.policies = self._load_policies(policy_path)
        self.inference = AttackTypeInference()
        self.responder = SafeLinuxResponder(allowlist_ips=allowlist_ips, dry_run=dry_run)
        self.action_logger = action_logger
        self.intel_share_callback = intel_share_callback
        self.threat_intel_callback = threat_intel_callback
        self.dashboard_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    @staticmethod
    def _load_policies(path: str) -> Dict[str, List[str]]:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return data.get("policies", {})

    def register_dashboard_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self.dashboard_callbacks.append(callback)

    def should_trigger(self, detection_result: Any) -> bool:
        confidence = float(getattr(detection_result, "confidence", 0.0) or 0.0)
        anomaly_score = float((getattr(detection_result, "metadata", {}) or {}).get("anomaly_score", 0.0) or 0.0)
        return confidence >= self.confidence_threshold or anomaly_score >= self.anomaly_threshold

    def trigger_async(self, detection_result: Any) -> None:
        thread = threading.Thread(target=self.process_detection, args=(detection_result,), daemon=True)
        thread.start()

    def process_detection(self, detection_result: Any) -> List[MitigationEvent]:
        attack_id = str(getattr(detection_result, "id", "")) or f"ATTACK-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        source_ip = str(getattr(detection_result, "source_ip", "") or "0.0.0.0")
        severity = str(getattr(getattr(detection_result, "severity", "medium"), "name", "medium")).lower()
        flow = getattr(detection_result, "raw_features", None) or getattr(detection_result, "metadata", {}) or {}
        inferred_attack_type = self.inference.infer(flow)
        attack_type = inferred_attack_type if inferred_attack_type != "unknown_zero_day" else str(getattr(detection_result, "attack_type", "unknown_zero_day"))

        actions = self.policies.get(severity, self.policies.get("low", ["alert_only"]))
        events: List[MitigationEvent] = []

        for action in actions:
            details = self._execute_action(attack_id=attack_id, action=action, source_ip=source_ip, flow=flow)
            event = MitigationEvent(
                attack_id=attack_id,
                attack_type=attack_type,
                source_ip=source_ip,
                severity=severity,
                action_taken=action,
                status=details.get("status", "unknown"),
                rollback_available=details.get("rollback_available", False),
                details=details,
            )
            self._emit_event(event)
            events.append(event)

        self._share_intel(attack_id=attack_id, attack_type=attack_type, source_ip=source_ip, severity=severity, actions=actions)
        return events

    def _execute_action(self, attack_id: str, action: str, source_ip: str, flow: Dict[str, Any]) -> Dict[str, Any]:
        if action == "block_ip":
            result = self.responder.block_ip_iptables(attack_id=attack_id, ip_value=source_ip)
            result["rollback_available"] = result.get("status") == "success"
            return result
        if action == "add_firewall_rule":
            result = self.responder.add_firewall_rule(attack_id=attack_id, ip_value=source_ip)
            result["rollback_available"] = result.get("status") == "success"
            return result
        if action == "kill_process":
            pid = int(flow.get("pid", 0) or 0)
            result = self.responder.kill_suspicious_process(attack_id=attack_id, pid=pid)
            result["rollback_available"] = False
            return result
        if action == "isolate_host":
            interface = str(flow.get("interface", "eth0") or "eth0")
            result = self.responder.isolate_host(attack_id=attack_id, interface=interface)
            result["rollback_available"] = result.get("status") == "success"
            return result
        if action == "rate_limit_ip":
            result = self.responder.rate_limit_ip(attack_id=attack_id, ip_value=source_ip)
            result["rollback_available"] = result.get("status") == "success"
            return result
        if action == "write_suricata_blocklist":
            result = self.responder.write_blocklist("runtime/suricata/blocklist.txt", source_ip)
            result["rollback_available"] = False
            return result
        if action == "write_zeek_blocklist":
            result = self.responder.write_blocklist("runtime/zeek/blocklist.txt", source_ip)
            result["rollback_available"] = False
            return result
        if action == "add_threat_intel":
            if self.threat_intel_callback:
                self.threat_intel_callback({
                    "indicator": source_ip,
                    "threat_type": "zero_day",
                    "confidence": 0.9,
                    "source": "autonomous_mitigation",
                })
            return {"status": "success", "rollback_available": False}
        if action == "alert_only":
            return {"status": "success", "rollback_available": False, "message": "Alert issued"}
        return {"status": "skipped", "rollback_available": False, "reason": f"unknown_action:{action}"}

    def rollback(self, attack_id: str) -> List[Dict[str, Any]]:
        return self.responder.rollback(attack_id)

    def _emit_event(self, event: MitigationEvent) -> None:
        if self.action_logger:
            self.action_logger(event)

        payload = {
            "attack_id": event.attack_id,
            "attack_type": event.attack_type,
            "source_ip": event.source_ip,
            "severity": event.severity,
            "action_taken": event.action_taken,
            "status": event.status,
            "timestamp": event.timestamp.isoformat(),
            "rollback_available": event.rollback_available,
            "details": event.details,
        }
        for callback in self.dashboard_callbacks:
            try:
                callback(payload)
            except Exception as exc:
                logger.error("Dashboard callback failed: %s", exc)

    def _share_intel(self, attack_id: str, attack_type: str, source_ip: str, severity: str, actions: List[str]) -> None:
        if not self.intel_share_callback:
            return
        anonymized = {
            "attack_id": attack_id,
            "attack_type": attack_type,
            "source_ip_hash": hash(source_ip),
            "severity": severity,
            "actions": actions,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.intel_share_callback(anonymized)


def mitigation_event_to_json(event: MitigationEvent) -> str:
    return json.dumps(
        {
            "attack_id": event.attack_id,
            "attack_type": event.attack_type,
            "source_ip": event.source_ip,
            "action_taken": event.action_taken,
            "timestamp": event.timestamp.isoformat(),
            "status": event.status,
            "rollback_available": event.rollback_available,
            "severity": event.severity,
            "details": event.details,
        }
    )
