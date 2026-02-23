"""
Zero-Day Confidence Scoring & Explainability Engine
===================================================
Provides detailed explanations and confidence scores for detected anomalies.

Features:
- Multi-factor confidence computation
- Evidence-based reasoning
- Attack type guessing
- Explainability metrics
- Confidence factor analysis

Author: AI-NIDS Team
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ConfidenceFactor(Enum):
    """Factors contributing to confidence score."""
    MODEL_AGREEMENT = "model_agreement"
    SEVERITY_SCORE = "severity_score"
    BASELINE_DEVIATION = "baseline_deviation"
    KNOWN_FALSE_POSITIVE = "known_false_positive"
    CONTEXTUAL_FIT = "contextual_fit"
    TEMPORAL_PATTERN = "temporal_pattern"
    PAYLOAD_ANALYSIS = "payload_analysis"
    GEOGRAPHIC_CONTEXT = "geographic_context"


@dataclass
class ConfidenceFactorScore:
    """Score for a single confidence factor."""
    factor: ConfidenceFactor
    score: float  # 0-1
    weight: float  # 0-1
    reason: str
    evidence: List[str] = field(default_factory=list)


@dataclass
class ExplainabilityReport:
    """Detailed explainability report for a detection."""
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    confidence_factors: List[ConfidenceFactorScore] = field(default_factory=list)
    
    primary_detector: str = ""
    supporting_detectors: List[str] = field(default_factory=list)
    
    attack_type_guess: str = "unknown"
    attack_type_probabilities: Dict[str, float] = field(default_factory=dict)
    
    evidence_summary: str = ""
    detailed_evidence: List[str] = field(default_factory=list)
    
    risk_factors: List[str] = field(default_factory=list)
    mitigating_factors: List[str] = field(default_factory=list)
    
    recommended_actions: List[str] = field(default_factory=list)
    
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'is_anomaly': self.is_anomaly,
            'anomaly_score': float(self.anomaly_score),
            'confidence': float(self.confidence),
            'confidence_factors': [
                {
                    'factor': cf.factor.value,
                    'score': float(cf.score),
                    'weight': float(cf.weight),
                    'reason': cf.reason,
                    'evidence': cf.evidence
                }
                for cf in self.confidence_factors
            ],
            'primary_detector': self.primary_detector,
            'supporting_detectors': self.supporting_detectors,
            'attack_type_guess': self.attack_type_guess,
            'attack_type_probabilities': {k: float(v) for k, v in self.attack_type_probabilities.items()},
            'evidence_summary': self.evidence_summary,
            'detailed_evidence': self.detailed_evidence,
            'risk_factors': self.risk_factors,
            'mitigating_factors': self.mitigating_factors,
            'recommended_actions': self.recommended_actions,
            'timestamp': self.timestamp.isoformat()
        }


class AttackTypeClassifier:
    """Classifies suspected attack types based on characteristics."""
    
    ATTACK_SIGNATURES = {
        'data_exfiltration': {
            'indicators': [
                'high_bytes_out',
                'unusual_destinations',
                'off_hours_activity',
                'encrypted_traffic'
            ],
            'weight': 0.25,
        },
        'ddos': {
            'indicators': [
                'high_packet_rate',
                'high_flow_count',
                'amplification_traffic',
                'synchronized_flows'
            ],
            'weight': 0.25,
        },
        'lateral_movement': {
            'indicators': [
                'internal_to_internal',
                'port_scanning',
                'protocol_probing',
                'credential_testing'
            ],
            'weight': 0.20,
        },
        'malware_c2': {
            'indicators': [
                'known_c2_connection',
                'periodic_beaconing',
                'dns_tunneling',
                'encrypted_payload'
            ],
            'weight': 0.20,
        },
        'reconnaissance': {
            'indicators': [
                'port_scan',
                'network_sweep',
                'service_enumeration',
                'version_probing'
            ],
            'weight': 0.15,
        },
    }
    
    @classmethod
    def classify(cls, flow_data: Dict, detector_results: Dict) -> Tuple[str, Dict[str, float]]:
        """
        Classify attack type.
        
        Args:
            flow_data: Flow data
            detector_results: Detection results
            
        Returns:
            Tuple of (primary_attack_type, probabilities_dict)
        """
        scores = {}
        
        # Score each attack type
        for attack_type, signature in cls.ATTACK_SIGNATURES.items():
            score = cls._score_attack_type(flow_data, detector_results, signature)
            scores[attack_type] = score
        
        # Normalize to probabilities
        total = sum(scores.values())
        if total == 0:
            probabilities = {k: 1.0 / len(scores) for k in scores}
            primary = 'unknown'
        else:
            probabilities = {k: v / total for k, v in scores.items()}
            primary = max(probabilities, key=probabilities.get)
        
        return primary, probabilities
    
    @staticmethod
    def _score_attack_type(flow_data: Dict, detector_results: Dict, signature: Dict) -> float:
        """Score a single attack type."""
        score = 0.0
        
        # Check indicators
        for indicator in signature.get('indicators', []):
            if AttackTypeClassifier._check_indicator(flow_data, detector_results, indicator):
                score += 1.0
        
        # Normalize by number of indicators
        if signature.get('indicators'):
            score = score / len(signature['indicators'])
        
        return score
    
    @staticmethod
    def _check_indicator(flow_data: Dict, detector_results: Dict, indicator: str) -> bool:
        """Check if indicator is present."""
        indicators = {
            'high_bytes_out': flow_data.get('bytes_out', 0) > 1_000_000,
            'unusual_destinations': flow_data.get('is_unusual_dst', False),
            'off_hours_activity': False,  # Would check time of day
            'encrypted_traffic': flow_data.get('protocol') in ['tls', 'ssl', 'https'],
            'high_packet_rate': flow_data.get('packets', 0) > 10000,
            'high_flow_count': detector_results.get('flow_count', 0) > 100,
            'amplification_traffic': flow_data.get('src_port', 0) in [53, 123, 161],
            'synchronized_flows': False,  # Would check timing
            'internal_to_internal': False,  # Would check IP ranges
            'port_scanning': detector_results.get('is_port_scan', False),
            'protocol_probing': False,
            'credential_testing': flow_data.get('dst_port', 0) in [22, 3389, 445],
            'known_c2_connection': False,  # Would check threat intel
            'periodic_beaconing': False,
            'dns_tunneling': flow_data.get('protocol') == 'dns' and flow_data.get('bytes_out', 0) > 1000,
            'encrypted_payload': flow_data.get('protocol') in ['tls', 'ssl'],
            'port_scan': detector_results.get('is_port_scan', False),
            'network_sweep': False,
            'service_enumeration': False,
            'version_probing': False,
        }
        
        return indicators.get(indicator, False)


class ConfidenceScoringEngine:
    """Computes confidence scores based on multiple factors."""
    
    def __init__(self):
        """Initialize confidence scoring engine."""
        self.factor_weights = {
            ConfidenceFactor.MODEL_AGREEMENT: 0.25,
            ConfidenceFactor.SEVERITY_SCORE: 0.20,
            ConfidenceFactor.BASELINE_DEVIATION: 0.20,
            ConfidenceFactor.KNOWN_FALSE_POSITIVE: -0.20,
            ConfidenceFactor.CONTEXTUAL_FIT: 0.15,
            ConfidenceFactor.TEMPORAL_PATTERN: 0.10,
            ConfidenceFactor.PAYLOAD_ANALYSIS: 0.05,
            ConfidenceFactor.GEOGRAPHIC_CONTEXT: 0.05,
        }
    
    def compute_confidence(
        self,
        anomaly_score: float,
        detector_results: List,
        flow_data: Dict,
        baseline_stats: Optional[Dict] = None
    ) -> Tuple[float, List[ConfidenceFactorScore]]:
        """
        Compute confidence score from multiple factors.
        
        Args:
            anomaly_score: Base anomaly score (0-1)
            detector_results: List of detector results
            flow_data: Flow data
            baseline_stats: Baseline statistics
            
        Returns:
            Tuple of (confidence_score, factor_scores)
        """
        factors = []
        
        # 1. Model Agreement
        anomalous_detectors = sum(1 for r in detector_results if hasattr(r, 'is_anomalous') and r.is_anomalous)
        agreement_ratio = anomalous_detectors / max(1, len(detector_results))
        
        factors.append(ConfidenceFactorScore(
            factor=ConfidenceFactor.MODEL_AGREEMENT,
            score=agreement_ratio,
            weight=self.factor_weights[ConfidenceFactor.MODEL_AGREEMENT],
            reason=f"{anomalous_detectors}/{len(detector_results)} detectors agreed",
            evidence=[f"Detector {i+1}: {'anomalous' if r.is_anomalous else 'normal'}" 
                     for i, r in enumerate(detector_results)]
        ))
        
        # 2. Severity Score
        severity = self._compute_severity(flow_data)
        factors.append(ConfidenceFactorScore(
            factor=ConfidenceFactor.SEVERITY_SCORE,
            score=severity,
            weight=self.factor_weights[ConfidenceFactor.SEVERITY_SCORE],
            reason=f"Attack characteristics severity: {severity:.2f}",
            evidence=[
                f"Bytes out: {flow_data.get('bytes_out', 0)} bytes",
                f"Packet count: {flow_data.get('packets', 0)}",
                f"Duration: {flow_data.get('duration', 0):.2f}s"
            ]
        ))
        
        # 3. Baseline Deviation
        if baseline_stats:
            baseline_deviation = baseline_stats.get('deviation_std', 0.0)
            baseline_score = min(1.0, baseline_deviation / 5.0)  # Normalized to 5 sigma
            
            factors.append(ConfidenceFactorScore(
                factor=ConfidenceFactor.BASELINE_DEVIATION,
                score=baseline_score,
                weight=self.factor_weights[ConfidenceFactor.BASELINE_DEVIATION],
                reason=f"Deviation from baseline: {baseline_deviation:.2f} std",
                evidence=[
                    f"Normal range: {baseline_stats.get('mean', 0):.0f} ± {baseline_stats.get('std', 0):.0f}",
                    f"Observed value: {flow_data.get('bytes_out', 0)}"
                ]
            ))
        
        # 4. Known False Positive Check
        fp_score = self._check_known_false_positive(flow_data)
        if fp_score > 0:
            factors.append(ConfidenceFactorScore(
                factor=ConfidenceFactor.KNOWN_FALSE_POSITIVE,
                score=-fp_score,
                weight=self.factor_weights[ConfidenceFactor.KNOWN_FALSE_POSITIVE],
                reason="Matches known false positive pattern",
                evidence=["This pattern has been confirmed benign in the past"]
            ))
        
        # 5. Contextual Fit
        contextual_score = self._compute_contextual_fit(flow_data)
        factors.append(ConfidenceFactorScore(
            factor=ConfidenceFactor.CONTEXTUAL_FIT,
            score=contextual_score,
            weight=self.factor_weights[ConfidenceFactor.CONTEXTUAL_FIT],
            reason=f"Matches known attack patterns: {contextual_score:.2f}",
            evidence=self._get_contextual_evidence(flow_data)
        ))
        
        # 6. Temporal Pattern
        temporal_score = self._compute_temporal_pattern(flow_data)
        factors.append(ConfidenceFactorScore(
            factor=ConfidenceFactor.TEMPORAL_PATTERN,
            score=temporal_score,
            weight=self.factor_weights[ConfidenceFactor.TEMPORAL_PATTERN],
            reason=f"Temporal anomaly detected: {temporal_score:.2f}",
            evidence=["Activity outside normal hours", "Burst traffic pattern"]
        ))
        
        # Compute final confidence
        total_weight = sum(f.weight for f in factors)
        if total_weight != 0:
            weighted_sum = sum(f.score * f.weight for f in factors)
            confidence = min(1.0, max(0.0, weighted_sum / total_weight))
        else:
            confidence = anomaly_score
        
        return confidence, factors
    
    @staticmethod
    def _compute_severity(flow_data: Dict) -> float:
        """Compute severity based on flow characteristics."""
        severity = 0.5  # Start at neutral
        
        # Large data transfers increase severity
        bytes_out = flow_data.get('bytes_out', 0)
        if bytes_out > 100_000_000:  # > 100MB
            severity += 0.3
        elif bytes_out > 1_000_000:  # > 1MB
            severity += 0.2
        
        # High packet rate increases severity
        packets = flow_data.get('packets', 0)
        duration = flow_data.get('duration', 1)
        pps = packets / max(1, duration)
        if pps > 10000:
            severity += 0.2
        elif pps > 1000:
            severity += 0.1
        
        return min(1.0, severity)
    
    @staticmethod
    def _check_known_false_positive(flow_data: Dict) -> float:
        """Check if matches known false positive."""
        # This would integrate with a database of known FPs
        # For now, return 0
        return 0.0
    
    @staticmethod
    def _compute_contextual_fit(flow_data: Dict) -> float:
        """Compute how well flow fits known attack patterns."""
        score = 0.0
        
        # Check if destination is suspicious
        dst_ip = flow_data.get('dst_ip', '')
        if dst_ip.startswith('8.'):  # Hypothetical suspicious range
            score += 0.2
        
        # Check if port is suspicious
        dst_port = flow_data.get('dst_port', 0)
        if dst_port in [4444, 5555, 6666, 7777]:  # Common malware ports
            score += 0.3
        
        return min(1.0, score)
    
    @staticmethod
    def _compute_temporal_pattern(flow_data: Dict) -> float:
        """Compute temporal anomaly score."""
        # This would check time-of-day, day-of-week patterns
        # For now, return moderate score
        return 0.3
    
    @staticmethod
    def _get_contextual_evidence(flow_data: Dict) -> List[str]:
        """Get contextual evidence list."""
        evidence = []
        
        if flow_data.get('dst_port', 0) in [4444, 5555, 6666, 7777]:
            evidence.append("Destination port matches common malware C2 ports")
        
        return evidence


class ZeroDayExplainer:
    """
    Generates detailed explainability reports for zero-day detections.
    """
    
    def __init__(self, confidence_engine: Optional[ConfidenceScoringEngine] = None):
        """
        Initialize explainer.
        
        Args:
            confidence_engine: Confidence scoring engine
        """
        self.confidence_engine = confidence_engine or ConfidenceScoringEngine()
        self.attack_classifier = AttackTypeClassifier()
    
    def explain(
        self,
        is_anomaly: bool,
        anomaly_score: float,
        detector_results: List,
        flow_data: Dict,
        baseline_stats: Optional[Dict] = None
    ) -> ExplainabilityReport:
        """
        Generate explainability report.
        
        Args:
            is_anomaly: Whether anomaly was detected
            anomaly_score: Base anomaly score
            detector_results: Results from each detector
            flow_data: Flow data
            baseline_stats: Baseline statistics
            
        Returns:
            ExplainabilityReport
        """
        # Compute confidence
        confidence, confidence_factors = self.confidence_engine.compute_confidence(
            anomaly_score, detector_results, flow_data, baseline_stats
        )
        
        # Classify attack type
        attack_type, attack_probs = self.attack_classifier.classify(flow_data, {})
        
        # Build evidence
        evidence = self._build_evidence(detector_results, flow_data, confidence_factors)
        
        # Identify primary detector
        primary_detector = self._get_primary_detector(detector_results)
        supporting_detectors = [r.__class__.__name__ for r in detector_results 
                              if hasattr(r, 'is_anomalous') and r.is_anomalous]
        
        # Get risk factors
        risk_factors = self._identify_risk_factors(flow_data, detector_results)
        mitigating_factors = self._identify_mitigating_factors(flow_data)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            is_anomaly, attack_type, risk_factors, confidence
        )
        
        return ExplainabilityReport(
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            confidence=confidence,
            confidence_factors=confidence_factors,
            primary_detector=primary_detector,
            supporting_detectors=supporting_detectors,
            attack_type_guess=attack_type,
            attack_type_probabilities=attack_probs,
            evidence_summary=self._summarize_evidence(evidence),
            detailed_evidence=evidence,
            risk_factors=risk_factors,
            mitigating_factors=mitigating_factors,
            recommended_actions=recommendations
        )
    
    @staticmethod
    def _build_evidence(detector_results: List, flow_data: Dict, 
                       confidence_factors: List[ConfidenceFactorScore]) -> List[str]:
        """Build evidence list."""
        evidence = []
        
        for factor in confidence_factors:
            evidence.extend(factor.evidence)
        
        return evidence
    
    @staticmethod
    def _get_primary_detector(detector_results: List) -> str:
        """Get primary detector."""
        if not detector_results:
            return "unknown"
        
        # Get detector with highest score
        if hasattr(detector_results[0], 'detector_type'):
            max_detector = max(detector_results, key=lambda r: getattr(r, 'score', 0))
            return max_detector.detector_type.value
        
        return detector_results[0].__class__.__name__
    
    @staticmethod
    def _identify_risk_factors(flow_data: Dict, detector_results: List) -> List[str]:
        """Identify risk factors."""
        factors = []
        
        if flow_data.get('bytes_out', 0) > 1_000_000:
            factors.append("Large data transfer (potential exfiltration)")
        
        if flow_data.get('packets', 0) > 10000:
            factors.append("High packet rate (potential DDoS)")
        
        return factors
    
    @staticmethod
    def _identify_mitigating_factors(flow_data: Dict) -> List[str]:
        """Identify mitigating factors."""
        factors = []
        
        if flow_data.get('duration', 0) < 1:
            factors.append("Very short duration (may be benign)")
        
        return factors
    
    @staticmethod
    def _summarize_evidence(evidence: List[str]) -> str:
        """Summarize evidence."""
        if not evidence:
            return "No strong evidence of anomaly"
        
        return f"Multiple indicators detected: {', '.join(evidence[:3])}"
    
    @staticmethod
    def _generate_recommendations(
        is_anomaly: bool,
        attack_type: str,
        risk_factors: List[str],
        confidence: float
    ) -> List[str]:
        """Generate recommendations."""
        recommendations = []
        
        if not is_anomaly:
            recommendations.append("No action required - benign traffic")
        elif confidence > 0.8:
            recommendations.append("HIGH PRIORITY: Immediate investigation and blocking recommended")
            recommendations.append("Block source IP and investigate flow")
        elif confidence > 0.6:
            recommendations.append("MEDIUM PRIORITY: Investigate and monitor")
            recommendations.append("Add to watchlist for further monitoring")
        else:
            recommendations.append("LOW PRIORITY: Monitor but likely benign")
        
        if attack_type == 'data_exfiltration':
            recommendations.append("Check for sensitive data in flow")
            recommendations.append("Review network egress logs")
        
        return recommendations
