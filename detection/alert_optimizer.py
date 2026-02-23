"""
Alert Optimizer & Deduplication Engine
======================================
Reduces false positives and alert fatigue through intelligent deduplication.

Features:
- Group similar alerts
- Escalate multi-flow attacks
- Suppress known false positives
- Rate limiting per source
- Confidence-based filtering

Author: AI-NIDS Team
"""

import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class AlertMetadata:
    """Metadata for an alert."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    anomaly_score: float
    confidence: float
    attack_type: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def get_hash(self) -> str:
        """Get hash of alert for deduplication."""
        key = f"{self.src_ip}_{self.dst_ip}_{self.dst_port}_{self.protocol}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def get_group_key(self) -> str:
        """Get key for grouping similar alerts."""
        return f"{self.src_ip}→{self.dst_ip}:{self.dst_port}"


@dataclass
class DedupedAlert:
    """Deduplicated alert (potentially aggregated from multiple flows)."""
    primary_alert: AlertMetadata
    duplicate_count: int = 1
    max_anomaly_score: float = 0.0
    avg_confidence: float = 0.0
    variants: List[AlertMetadata] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    escalation_level: int = 0  # 0=single, 1=multiple IPs, 2=coordinated
    suppressed: bool = False
    suppression_reason: Optional[str] = None


class AlertGrouper:
    """Groups similar alerts for aggregation."""
    
    def __init__(self, time_window: int = 30):
        """
        Initialize alert grouper.
        
        Args:
            time_window: Time window in seconds for grouping
        """
        self.time_window = time_window
        self.alert_groups = defaultdict(list)
        self.group_timers = {}
        
    def add_alert(self, alert: AlertMetadata) -> Optional[str]:
        """
        Add alert to a group.
        
        Args:
            alert: Alert metadata
            
        Returns:
            Group ID if created, None otherwise
        """
        group_key = alert.get_group_key()
        
        self.alert_groups[group_key].append(alert)
        
        if group_key not in self.group_timers:
            self.group_timers[group_key] = datetime.utcnow()
            return group_key
        
        return None
    
    def get_expired_groups(self) -> List[str]:
        """Get groups that have expired."""
        now = datetime.utcnow()
        expired = []
        
        for group_key, created_time in self.group_timers.items():
            if (now - created_time).total_seconds() > self.time_window:
                expired.append(group_key)
        
        return expired
    
    def flush_group(self, group_key: str) -> List[AlertMetadata]:
        """
        Flush a group and return its alerts.
        
        Args:
            group_key: Group identifier
            
        Returns:
            List of alerts in the group
        """
        alerts = self.alert_groups.pop(group_key, [])
        self.group_timers.pop(group_key, None)
        return alerts
    
    def get_group_stats(self, group_key: str) -> Dict:
        """Get statistics for a group."""
        alerts = self.alert_groups.get(group_key, [])
        
        if not alerts:
            return {}
        
        return {
            'count': len(alerts),
            'max_anomaly_score': max(a.anomaly_score for a in alerts),
            'avg_confidence': sum(a.confidence for a in alerts) / len(alerts),
            'unique_ips': len(set(a.src_ip for a in alerts)),
            'time_span': (alerts[-1].timestamp - alerts[0].timestamp).total_seconds()
        }


class FalsePositiveSuppressor:
    """Suppresses known false positives."""
    
    def __init__(self):
        """Initialize suppressor."""
        self.suppression_rules = [
            self._suppress_scanning_tools,
            self._suppress_testing_traffic,
            self._suppress_legitimate_scanners,
            self._suppress_low_confidence,
        ]
        
        # Known benign patterns
        self.known_benign_ips = set()
        self.known_benign_patterns = set()
        self.feedback_log = deque(maxlen=10000)
        
    def should_suppress(self, alert: AlertMetadata) -> Tuple[bool, Optional[str]]:
        """
        Check if alert should be suppressed.
        
        Args:
            alert: Alert to check
            
        Returns:
            Tuple of (should_suppress, reason)
        """
        for rule in self.suppression_rules:
            should_suppress, reason = rule(alert)
            if should_suppress:
                return True, reason
        
        return False, None
    
    def _suppress_scanning_tools(self, alert: AlertMetadata) -> Tuple[bool, Optional[str]]:
        """Suppress known vulnerability scanning tools."""
        scanning_ports = {80, 443, 8080, 8443}
        benign_user_agents = ['nessus', 'qualys', 'openvas', 'nikto']
        
        # Suppress if scanning common ports
        if alert.dst_port in scanning_ports and alert.attack_type in ['port_scan', 'web_scan']:
            return True, "Known scanning tool activity"
        
        return False, None
    
    def _suppress_testing_traffic(self, alert: AlertMetadata) -> Tuple[bool, Optional[str]]:
        """Suppress testing/training traffic."""
        # Internal testing subnets
        testing_ranges = ['192.168.0.0/16', '10.0.0.0/8']
        
        # If both src and dst are internal, might be testing
        if self._is_internal_ip(alert.src_ip) and self._is_internal_ip(alert.dst_ip):
            if alert.confidence < 0.3:
                return True, "Low-confidence internal traffic (likely testing)"
        
        return False, None
    
    def _suppress_legitimate_scanners(self, alert: AlertMetadata) -> Tuple[bool, Optional[str]]:
        """Suppress legitimate security tools."""
        if alert.src_ip in self.known_benign_ips:
            return True, "Known benign IP"
        
        return False, None
    
    def _suppress_low_confidence(self, alert: AlertMetadata) -> Tuple[bool, Optional[str]]:
        """Suppress very low confidence alerts."""
        if alert.confidence < 0.2:
            return True, "Confidence too low (< 0.2)"
        
        return False, None
    
    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        """Check if IP is internal."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        first_octet = int(parts[0])
        
        # 10.0.0.0/8
        if first_octet == 10:
            return True
        
        # 172.16.0.0/12
        if first_octet == 172 and 16 <= int(parts[1]) <= 31:
            return True
        
        # 192.168.0.0/16
        if first_octet == 192 and int(parts[1]) == 168:
            return True
        
        # 127.0.0.0/8 (loopback)
        if first_octet == 127:
            return True
        
        return False
    
    def add_feedback(self, alert_hash: str, is_true_positive: bool):
        """
        Add analyst feedback.
        
        Args:
            alert_hash: Alert identifier
            is_true_positive: True if legitimate threat
        """
        self.feedback_log.append({
            'alert_hash': alert_hash,
            'is_tp': is_true_positive,
            'timestamp': datetime.utcnow()
        })


class EscalationEngine:
    """Escalates severity of multi-flow attacks."""
    
    @staticmethod
    def escalate_alert(alerts: List[AlertMetadata]) -> Tuple[int, str]:
        """
        Escalate alert based on multiple flows.
        
        Args:
            alerts: List of related alerts
            
        Returns:
            Tuple of (escalation_level, reason)
        """
        if len(alerts) < 2:
            return 0, "Single flow"
        
        # Extract unique values
        unique_src_ips = set(a.src_ip for a in alerts)
        unique_dst_ips = set(a.dst_ip for a in alerts)
        
        time_span = (alerts[-1].timestamp - alerts[0].timestamp).total_seconds()
        
        # Level 1: Multiple flows from same source
        if len(alerts) >= 5 and time_span < 60:
            return 1, f"Multiple flows ({len(alerts)}) in {time_span}s from same source"
        
        # Level 2: Coordinated attack (multiple sources to same target)
        if len(unique_src_ips) >= 3 and len(unique_dst_ips) == 1:
            return 2, f"Coordinated attack from {len(unique_src_ips)} sources"
        
        # Level 3: Distributed attack (many to many)
        if len(unique_src_ips) >= 3 and len(unique_dst_ips) >= 3:
            return 3, f"Distributed attack: {len(unique_src_ips)} sources to {len(unique_dst_ips)} targets"
        
        return 0, "Single or low-volume attack"


class AlertOptimizer:
    """
    Main alert optimization engine.
    Deduplicates, groups, escalates, and suppresses alerts.
    """
    
    def __init__(self, grouping_window: int = 30, max_queue_size: int = 10000):
        """
        Initialize alert optimizer.
        
        Args:
            grouping_window: Time window for grouping (seconds)
            max_queue_size: Maximum pending alerts
        """
        self.grouper = AlertGrouper(time_window=grouping_window)
        self.suppressor = FalsePositiveSuppressor()
        self.escalator = EscalationEngine()
        
        self.recent_alerts = deque(maxlen=max_queue_size)
        self.deduped_alerts = {}
        self.stats = {
            'total_alerts_received': 0,
            'alerts_suppressed': 0,
            'alerts_deduplicated': 0,
            'alerts_escalated': 0,
            'alerts_emitted': 0,
        }
    
    def process_alert(self, alert: AlertMetadata) -> Optional[DedupedAlert]:
        """
        Process a single alert.
        
        Args:
            alert: Alert to process
            
        Returns:
            DedupedAlert if should emit, None otherwise
        """
        self.stats['total_alerts_received'] += 1
        
        # Check for suppression
        should_suppress, reason = self.suppressor.should_suppress(alert)
        if should_suppress:
            self.stats['alerts_suppressed'] += 1
            logger.debug(f"Suppressed alert from {alert.src_ip}: {reason}")
            return None
        
        # Group with similar alerts
        self.grouper.add_alert(alert)
        self.recent_alerts.append(alert)
        
        return None  # Return after grouping window expires
    
    def flush_pending_alerts(self) -> List[DedupedAlert]:
        """
        Flush pending alerts that have expired their grouping window.
        
        Returns:
            List of deduped alerts ready to emit
        """
        output_alerts = []
        
        for group_key in self.grouper.get_expired_groups():
            alerts = self.grouper.flush_group(group_key)
            
            if not alerts:
                continue
            
            # Create deduped alert
            primary = alerts[0]
            deduped = DedupedAlert(
                primary_alert=primary,
                duplicate_count=len(alerts),
                max_anomaly_score=max(a.anomaly_score for a in alerts),
                avg_confidence=sum(a.confidence for a in alerts) / len(alerts),
                variants=alerts[1:],
                first_seen=alerts[0].timestamp,
                last_seen=alerts[-1].timestamp,
            )
            
            # Escalate if necessary
            escalation_level, reason = self.escalator.escalate_alert(alerts)
            deduped.escalation_level = escalation_level
            
            if escalation_level > 0:
                self.stats['alerts_escalated'] += 1
                logger.warning(f"Escalated alert: {reason}")
            
            self.stats['alerts_deduplicated'] += len(alerts) - 1
            self.stats['alerts_emitted'] += 1
            
            output_alerts.append(deduped)
        
        return output_alerts
    
    def get_stats(self) -> Dict:
        """Get optimizer statistics."""
        return {
            **self.stats,
            'pending_groups': len(self.grouper.alert_groups),
            'recent_alerts_queue_size': len(self.recent_alerts),
            'deduplication_ratio': (
                self.stats['alerts_deduplicated'] / max(1, self.stats['total_alerts_received'])
            )
        }
    
    def register_benign_ip(self, ip: str):
        """Register an IP as benign."""
        self.suppressor.known_benign_ips.add(ip)
        logger.info(f"Registered benign IP: {ip}")
    
    def unregister_benign_ip(self, ip: str):
        """Unregister a benign IP."""
        self.suppressor.known_benign_ips.discard(ip)
        logger.info(f"Unregistered benign IP: {ip}")
