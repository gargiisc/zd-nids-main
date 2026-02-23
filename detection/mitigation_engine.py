"""
Mitigation Engine for AI-NIDS
==============================
Generates and executes mitigation strategies for detected threats.
Provides attack-type specific remediation techniques.

Author: AI-NIDS Team
"""

import logging
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)


class MitigationAction(Enum):
    """Types of mitigation actions."""
    BLOCK_IP = "block_ip"
    BLOCK_PORT = "block_port"
    RATE_LIMIT = "rate_limit"
    ISOLATE_HOST = "isolate_host"
    ISOLATE_SUBNET = "isolate_subnet"
    DEEP_PACKET_INSPECTION = "deep_packet_inspection"
    ALERT_SOC = "alert_soc"
    QUARANTINE = "quarantine"
    PATCH = "patch"
    UPDATE_WAF = "update_waf"
    RESET_CREDENTIALS = "reset_credentials"
    ENABLE_MFA = "enable_mfa"
    INCREASE_MONITORING = "increase_monitoring"
    CAPTURE_TRAFFIC = "capture_traffic"


class Severity(Enum):
    """Threat severity levels."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class MitigationStep:
    """Single mitigation step."""
    action: MitigationAction
    target: str  # IP, port, service, hostname
    description: str
    command: Optional[str] = None
    priority: int = 1  # 1=highest
    is_automated: bool = False
    automation_threshold: float = 0.9  # Confidence threshold for auto-execution
    estimated_impact: str = "high"  # high, medium, low
    requires_approval: bool = True
    rollback_possible: bool = True
    duration_hours: int = 24  # How long to apply mitigation
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'action': self.action.value,
            'target': self.target,
            'description': self.description,
            'command': self.command,
            'priority': self.priority,
            'is_automated': self.is_automated,
            'automation_threshold': self.automation_threshold,
            'estimated_impact': self.estimated_impact,
            'requires_approval': self.requires_approval,
            'rollback_possible': self.rollback_possible,
            'duration_hours': self.duration_hours
        }


@dataclass
class MitigationStrategy:
    """Complete mitigation strategy for an alert."""
    alert_id: int
    attack_type: str
    severity: Severity
    source_ip: str
    destination_ip: str
    
    # Mitigation Plan
    steps: List[MitigationStep] = field(default_factory=list)
    
    # Timing
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Metadata
    context: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'attack_type': self.attack_type,
            'severity': self.severity.name,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'steps': [step.to_dict() for step in self.steps],
            'created_at': self.created_at.isoformat(),
            'total_steps': len(self.steps),
            'estimated_time_to_implement': sum([60 * (5 - s.priority) for s in self.steps])  # seconds
        }


class MitigationEngine:
    """
    Generates mitigation strategies for detected threats.
    Maps attack types to recommended remediation techniques.
    """
    
    # Attack-type to mitigation mapping
    MITIGATION_MATRIX = {
        'DDoS': {
            'severity_critical': [
                {'action': MitigationAction.BLOCK_IP, 'target_type': 'source_ip', 'priority': 1},
                {'action': MitigationAction.RATE_LIMIT, 'target_type': 'port', 'priority': 2},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 1},
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'global', 'priority': 3},
            ],
            'severity_high': [
                {'action': MitigationAction.RATE_LIMIT, 'target_type': 'port', 'priority': 1},
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'subnet', 'priority': 2},
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 3},
            ],
            'severity_medium': [
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'subnet', 'priority': 1},
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 2},
            ]
        },
        'Port Scan': {
            'severity_high': [
                {'action': MitigationAction.BLOCK_IP, 'target_type': 'source_ip', 'priority': 1},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 2},
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'subnet', 'priority': 3},
            ],
            'severity_medium': [
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'subnet', 'priority': 1},
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 2},
            ],
            'severity_low': [
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'host', 'priority': 1},
            ]
        },
        'Brute Force': {
            'severity_critical': [
                {'action': MitigationAction.BLOCK_IP, 'target_type': 'source_ip', 'priority': 1},
                {'action': MitigationAction.RESET_CREDENTIALS, 'target_type': 'host', 'priority': 1},
                {'action': MitigationAction.ENABLE_MFA, 'target_type': 'host', 'priority': 2},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 1},
            ],
            'severity_high': [
                {'action': MitigationAction.BLOCK_IP, 'target_type': 'source_ip', 'priority': 1},
                {'action': MitigationAction.RATE_LIMIT, 'target_type': 'port', 'priority': 2},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 2},
            ],
            'severity_medium': [
                {'action': MitigationAction.RATE_LIMIT, 'target_type': 'port', 'priority': 1},
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'subnet', 'priority': 2},
            ]
        },
        'SQL Injection': {
            'severity_critical': [
                {'action': MitigationAction.ISOLATE_HOST, 'target_type': 'host', 'priority': 1},
                {'action': MitigationAction.UPDATE_WAF, 'target_type': 'waf', 'priority': 1},
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 2},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 1},
            ],
            'severity_high': [
                {'action': MitigationAction.UPDATE_WAF, 'target_type': 'waf', 'priority': 1},
                {'action': MitigationAction.DEEP_PACKET_INSPECTION, 'target_type': 'port', 'priority': 2},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 2},
            ],
            'severity_medium': [
                {'action': MitigationAction.UPDATE_WAF, 'target_type': 'waf', 'priority': 1},
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'host', 'priority': 2},
            ]
        },
        'Malware': {
            'severity_critical': [
                {'action': MitigationAction.ISOLATE_HOST, 'target_type': 'host', 'priority': 1},
                {'action': MitigationAction.QUARANTINE, 'target_type': 'host', 'priority': 1},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 1},
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 2},
            ],
            'severity_high': [
                {'action': MitigationAction.ISOLATE_HOST, 'target_type': 'host', 'priority': 1},
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'subnet', 'priority': 2},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 2},
            ]
        },
        'Data Exfiltration': {
            'severity_critical': [
                {'action': MitigationAction.BLOCK_IP, 'target_type': 'destination_ip', 'priority': 1},
                {'action': MitigationAction.ISOLATE_HOST, 'target_type': 'source_host', 'priority': 1},
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 1},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 1},
            ],
            'severity_high': [
                {'action': MitigationAction.RATE_LIMIT, 'target_type': 'destination_ip', 'priority': 1},
                {'action': MitigationAction.DEEP_PACKET_INSPECTION, 'target_type': 'port', 'priority': 2},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 2},
            ]
        },
        'Web Attack': {
            'severity_critical': [
                {'action': MitigationAction.UPDATE_WAF, 'target_type': 'waf', 'priority': 1},
                {'action': MitigationAction.DEEP_PACKET_INSPECTION, 'target_type': 'port', 'priority': 1},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 1},
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 2},
            ],
            'severity_high': [
                {'action': MitigationAction.UPDATE_WAF, 'target_type': 'waf', 'priority': 1},
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'host', 'priority': 2},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 2},
            ]
        },
        'Bot': {
            'severity_critical': [
                {'action': MitigationAction.ISOLATE_HOST, 'target_type': 'host', 'priority': 1},
                {'action': MitigationAction.QUARANTINE, 'target_type': 'host', 'priority': 1},
                {'action': MitigationAction.RESET_CREDENTIALS, 'target_type': 'host', 'priority': 1},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 1},
            ],
            'severity_high': [
                {'action': MitigationAction.ISOLATE_HOST, 'target_type': 'host', 'priority': 1},
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 2},
            ]
        }
    }
    
    def __init__(self):
        """Initialize mitigation engine."""
        self.logger = logging.getLogger(__name__)
    
    def generate_mitigation_strategy(
        self,
        alert_id: int,
        attack_type: str,
        severity: Severity,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: str,
        confidence: float,
        additional_context: Optional[Dict] = None
    ) -> MitigationStrategy:
        """
        Generate mitigation strategy for an alert.
        
        Args:
            alert_id: Alert ID
            attack_type: Type of attack
            severity: Severity level
            source_ip: Source IP address
            destination_ip: Destination IP address
            source_port: Source port
            destination_port: Destination port
            protocol: Protocol (TCP/UDP/ICMP)
            confidence: Detection confidence
            additional_context: Additional context for mitigation
            
        Returns:
            MitigationStrategy with recommended steps
        """
        context = additional_context or {}
        strategy = MitigationStrategy(
            alert_id=alert_id,
            attack_type=attack_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            context=context
        )
        
        # Get base mitigation recommendations
        severity_key = f'severity_{severity.name.lower()}'
        base_mitigations = self.MITIGATION_MATRIX.get(attack_type, {}).get(severity_key, [])
        
        if not base_mitigations:
            # Fallback to generic mitigations
            base_mitigations = self._get_generic_mitigations(severity)
        
        # Convert to MitigationSteps
        for i, mit in enumerate(base_mitigations):
            step = self._create_mitigation_step(
                action=MitigationAction(mit['action'].value if isinstance(mit['action'], MitigationAction) else mit['action']),
                target_type=mit['target_type'],
                source_ip=source_ip,
                destination_ip=destination_ip,
                port=destination_port,
                priority=mit['priority'],
                confidence=confidence
            )
            strategy.steps.append(step)
        
        # Sort by priority
        strategy.steps.sort(key=lambda x: x.priority)
        
        return strategy
    
    def _create_mitigation_step(
        self,
        action: MitigationAction,
        target_type: str,
        source_ip: str,
        destination_ip: str,
        port: int,
        priority: int,
        confidence: float
    ) -> MitigationStep:
        """Create a mitigation step."""
        
        target = self._get_target(target_type, source_ip, destination_ip, port)
        description = self._get_description(action, target_type, target)
        command = self._get_command(action, target)
        
        is_automated = priority <= 2 and confidence >= 0.85
        automation_threshold = 0.85 if priority <= 2 else 0.95
        
        return MitigationStep(
            action=action,
            target=target,
            description=description,
            command=command,
            priority=priority,
            is_automated=is_automated,
            automation_threshold=automation_threshold,
            estimated_impact=self._get_impact(priority),
            requires_approval=priority <= 2,
            rollback_possible=action in [
                MitigationAction.BLOCK_IP,
                MitigationAction.RATE_LIMIT,
                MitigationAction.ISOLATE_HOST,
                MitigationAction.ISOLATE_SUBNET
            ]
        )
    
    def _get_target(
        self,
        target_type: str,
        source_ip: str,
        destination_ip: str,
        port: int
    ) -> str:
        """Determine the target for the mitigation."""
        mapping = {
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'source_host': source_ip,
            'host': destination_ip,
            'port': str(port),
            'waf': 'Web Application Firewall',
            'soc': 'Security Operations Center',
            'subnet': self._get_subnet(destination_ip),
            'global': 'All Traffic'
        }
        return mapping.get(target_type, 'Unknown')
    
    def _get_subnet(self, ip: str) -> str:
        """Extract subnet from IP (simplified)."""
        try:
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            return "0.0.0.0/0"
    
    def _get_description(self, action: MitigationAction, target_type: str, target: str) -> str:
        """Get human-readable description."""
        descriptions = {
            MitigationAction.BLOCK_IP: f"Block all traffic from/to {target}",
            MitigationAction.RATE_LIMIT: f"Rate limit traffic on port {target}",
            MitigationAction.ISOLATE_HOST: f"Isolate host {target} from network",
            MitigationAction.ISOLATE_SUBNET: f"Isolate subnet {target} from network",
            MitigationAction.DEEP_PACKET_INSPECTION: f"Enable DPI on port {target}",
            MitigationAction.ALERT_SOC: "Alert Security Operations Center immediately",
            MitigationAction.QUARANTINE: f"Quarantine host {target}",
            MitigationAction.PATCH: f"Apply security patches to {target}",
            MitigationAction.UPDATE_WAF: "Update Web Application Firewall rules",
            MitigationAction.RESET_CREDENTIALS: f"Force password reset for {target}",
            MitigationAction.ENABLE_MFA: f"Enable multi-factor authentication on {target}",
            MitigationAction.INCREASE_MONITORING: f"Increase monitoring for {target}",
            MitigationAction.CAPTURE_TRAFFIC: f"Capture network traffic for analysis"
        }
        return descriptions.get(action, f"Execute {action.value} on {target}")
    
    def _get_command(self, action: MitigationAction, target: str) -> Optional[str]:
        """Get shell command for execution."""
        commands = {
            MitigationAction.BLOCK_IP: f"iptables -I INPUT -s {target} -j DROP",
            MitigationAction.RATE_LIMIT: f"tc qdisc add dev eth0 root tbf rate 100mbit burst 32kbit latency 400ms",
            MitigationAction.ISOLATE_HOST: f"virsh suspend {target}",  # Hypervisor example
            MitigationAction.QUARANTINE: f"vlan config add {target} 999",
            MitigationAction.UPDATE_WAF: "sudo /opt/modsecurity/update_rules.sh",
        }
        return commands.get(action, None)
    
    def _get_impact(self, priority: int) -> str:
        """Get impact level."""
        if priority <= 2:
            return "high"
        elif priority <= 5:
            return "medium"
        else:
            return "low"
    
    def _get_generic_mitigations(self, severity: Severity) -> List[Dict]:
        """Get generic mitigations for unknown attack types."""
        severity_map = {
            Severity.CRITICAL: [
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 1},
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'global', 'priority': 2},
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 3},
            ],
            Severity.HIGH: [
                {'action': MitigationAction.ALERT_SOC, 'target_type': 'soc', 'priority': 1},
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'global', 'priority': 2},
            ],
            Severity.MEDIUM: [
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'global', 'priority': 1},
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 2},
            ],
            Severity.LOW: [
                {'action': MitigationAction.INCREASE_MONITORING, 'target_type': 'global', 'priority': 1},
            ],
            Severity.INFO: [
                {'action': MitigationAction.CAPTURE_TRAFFIC, 'target_type': 'global', 'priority': 1},
            ]
        }
        
        return severity_map.get(severity, [])
    
    def calculate_mitigation_effectiveness(
        self,
        alert_count_before: int,
        alert_count_after: int,
        time_period_hours: int
    ) -> float:
        """
        Calculate effectiveness of mitigation.
        
        Returns:
            Effectiveness score 0.0 to 1.0
        """
        if alert_count_before == 0:
            return 1.0
        
        reduction_rate = (alert_count_before - alert_count_after) / alert_count_before
        return min(1.0, max(0.0, reduction_rate))
