"""
Real-Time Zero-Day Detection Engine
====================================
Detects previously unknown attacks through ensemble anomaly detection.

Combines:
- Autoencoder reconstruction error
- Isolation Forest anomaly scoring
- Statistical deviation (Z-score, MAD)
- Behavioral baseline comparison
- Temporal spike detection
- Entropy-based anomaly detection

Author: AI-NIDS Team
Version: 2.0.0 (Real-Time Streaming)
"""

import numpy as np
import torch
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque
import logging
import json
from enum import Enum

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of anomalies detected."""
    RECONSTRUCTION_ERROR = "reconstruction_error"
    ISOLATION_FOREST = "isolation_forest"
    STATISTICAL = "statistical"
    BASELINE_DEVIATION = "baseline_deviation"
    TEMPORAL_SPIKE = "temporal_spike"
    ENTROPY_ANOMALY = "entropy_anomaly"


@dataclass
class AnomalyDetectionResult:
    """Result from single anomaly detector."""
    detector_type: AnomalyType
    score: float  # 0-1
    is_anomalous: bool
    reason: str
    threshold: float
    raw_value: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ZeroDayDetectionResult:
    """Comprehensive zero-day detection result."""
    is_anomaly: bool
    anomaly_score: float  # 0-1 (ensemble)
    confidence: float  # 0-1 (how confident are we?)
    
    # Per-detector results
    detector_scores: Dict[str, float] = field(default_factory=dict)
    detector_results: List[AnomalyDetectionResult] = field(default_factory=list)
    
    # Reasoning
    primary_detectors: List[str] = field(default_factory=list)  # Which detectors triggered
    reasoning: str = ""
    evidence: List[str] = field(default_factory=list)
    
    # Flow info
    flow_key: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Context
    baseline_deviation_std: float = 0.0
    anomaly_type_guess: str = "unknown"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'is_anomaly': self.is_anomaly,
            'anomaly_score': float(self.anomaly_score),
            'confidence': float(self.confidence),
            'detector_scores': {k: float(v) for k, v in self.detector_scores.items()},
            'primary_detectors': self.primary_detectors,
            'reasoning': self.reasoning,
            'evidence': self.evidence,
            'baseline_deviation_std': float(self.baseline_deviation_std),
            'anomaly_type_guess': self.anomaly_type_guess,
            'timestamp': self.timestamp.isoformat()
        }


class ReconstructionErrorDetector:
    """Detects anomalies based on autoencoder reconstruction error."""
    
    def __init__(self, threshold_percentile: float = 95.0):
        self.threshold_percentile = threshold_percentile
        self.threshold = 0.5  # Default, will be updated
        self.error_history = deque(maxlen=10000)
        
    def detect(self, features: np.ndarray, model_output: np.ndarray) -> AnomalyDetectionResult:
        """
        Detect anomaly based on reconstruction error.
        
        Args:
            features: Original feature vector
            model_output: Autoencoder output
            
        Returns:
            AnomalyDetectionResult
        """
        # Calculate reconstruction error (MSE)
        error = float(np.mean((features - model_output) ** 2))
        self.error_history.append(error)
        
        # Update threshold dynamically
        if len(self.error_history) > 100:
            self.threshold = np.percentile(self.error_history, self.threshold_percentile)
        
        # Normalize to 0-1
        if self.threshold > 0:
            anomaly_score = min(1.0, error / (self.threshold * 2))
        else:
            anomaly_score = 0.5
        
        is_anomalous = error > self.threshold
        
        return AnomalyDetectionResult(
            detector_type=AnomalyType.RECONSTRUCTION_ERROR,
            score=anomaly_score,
            is_anomalous=is_anomalous,
            reason=f"Reconstruction error: {error:.4f} (threshold: {self.threshold:.4f})",
            threshold=self.threshold,
            raw_value=error
        )


class StatisticalAnomalyDetector:
    """Detects anomalies using Z-score and MAD (Median Absolute Deviation)."""
    
    def __init__(self, z_threshold: float = 3.0):
        self.z_threshold = z_threshold
        self.feature_history = deque(maxlen=1000)
        
    def detect(self, features: np.ndarray) -> AnomalyDetectionResult:
        """
        Detect anomaly using statistical methods.
        
        Args:
            features: Feature vector
            
        Returns:
            AnomalyDetectionResult
        """
        self.feature_history.append(features)
        
        if len(self.feature_history) < 30:
            return AnomalyDetectionResult(
                detector_type=AnomalyType.STATISTICAL,
                score=0.0,
                is_anomalous=False,
                reason="Insufficient history for statistical analysis",
                threshold=self.z_threshold
            )
        
        # Convert to numpy array
        history = np.array(list(self.feature_history))
        
        # Calculate Z-scores
        mean = np.mean(history, axis=0)
        std = np.std(history, axis=0)
        
        # Handle zero std
        std = np.where(std == 0, 1e-6, std)
        
        z_scores = np.abs((features - mean) / std)
        max_z_score = float(np.max(z_scores))
        mean_z_score = float(np.mean(z_scores))
        
        is_anomalous = max_z_score > self.z_threshold
        anomaly_score = min(1.0, mean_z_score / self.z_threshold)
        
        return AnomalyDetectionResult(
            detector_type=AnomalyType.STATISTICAL,
            score=anomaly_score,
            is_anomalous=is_anomalous,
            reason=f"Z-score anomaly: max={max_z_score:.2f}, mean={mean_z_score:.2f}",
            threshold=self.z_threshold,
            raw_value=max_z_score
        )


class TemporalAnomalyDetector:
    """Detects temporal spikes and unusual patterns."""
    
    def __init__(self, window_size: int = 100, spike_threshold: float = 2.0):
        self.window_size = window_size
        self.spike_threshold = spike_threshold
        self.flow_rates = deque(maxlen=window_size)
        self.byte_rates = deque(maxlen=window_size)
        
    def detect(self, bytes_sent: float, packet_count: float, duration: float) -> AnomalyDetectionResult:
        """
        Detect temporal anomalies.
        
        Args:
            bytes_sent: Bytes transmitted
            packet_count: Number of packets
            duration: Flow duration in seconds
            
        Returns:
            AnomalyDetectionResult
        """
        # Calculate rates
        flow_rate = packet_count / (duration + 1e-6)
        byte_rate = bytes_sent / (duration + 1e-6)
        
        self.flow_rates.append(flow_rate)
        self.byte_rates.append(byte_rate)
        
        if len(self.flow_rates) < 10:
            return AnomalyDetectionResult(
                detector_type=AnomalyType.TEMPORAL_SPIKE,
                score=0.0,
                is_anomalous=False,
                reason="Insufficient temporal history",
                threshold=self.spike_threshold
            )
        
        # Check for spikes
        mean_flow = np.mean(self.flow_rates)
        std_flow = np.std(self.flow_rates)
        
        flow_spike = (flow_rate - mean_flow) / (std_flow + 1e-6)
        byte_spike = max(0, (byte_rate - np.mean(self.byte_rates)) / (np.std(self.byte_rates) + 1e-6))
        
        max_spike = max(abs(flow_spike), abs(byte_spike))
        is_anomalous = max_spike > self.spike_threshold
        anomaly_score = min(1.0, max_spike / (self.spike_threshold * 2))
        
        return AnomalyDetectionResult(
            detector_type=AnomalyType.TEMPORAL_SPIKE,
            score=anomaly_score,
            is_anomalous=is_anomalous,
            reason=f"Temporal spike: flow_spike={flow_spike:.2f}, byte_spike={byte_spike:.2f}",
            threshold=self.spike_threshold,
            raw_value=max_spike
        )


class EntropyAnomalyDetector:
    """Detects anomalies using entropy-based analysis."""
    
    def __init__(self, threshold: float = 3.0):
        self.threshold = threshold
        self.entropy_history = deque(maxlen=1000)
        
    def detect(self, flow_data: Dict) -> AnomalyDetectionResult:
        """
        Detect anomalies using entropy.
        
        Args:
            flow_data: Flow dictionary with packet data
            
        Returns:
            AnomalyDetectionResult
        """
        # Calculate entropy from payload if available
        payload = flow_data.get('payload', b'')
        entropy = self._calculate_entropy(payload if isinstance(payload, bytes) else str(payload).encode())
        
        self.entropy_history.append(entropy)
        
        if len(self.entropy_history) < 30:
            return AnomalyDetectionResult(
                detector_type=AnomalyType.ENTROPY_ANOMALY,
                score=0.0,
                is_anomalous=False,
                reason="Insufficient entropy history",
                threshold=self.threshold
            )
        
        mean_entropy = np.mean(self.entropy_history)
        std_entropy = np.std(self.entropy_history)
        
        if std_entropy > 0:
            z_score = abs((entropy - mean_entropy) / std_entropy)
        else:
            z_score = 0
        
        is_anomalous = z_score > self.threshold
        anomaly_score = min(1.0, z_score / (self.threshold * 2))
        
        return AnomalyDetectionResult(
            detector_type=AnomalyType.ENTROPY_ANOMALY,
            score=anomaly_score,
            is_anomalous=is_anomalous,
            reason=f"High entropy: {entropy:.2f} (mean: {mean_entropy:.2f})",
            threshold=self.threshold,
            raw_value=entropy
        )
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        entropy = -np.sum(probabilities[probabilities > 0] * np.log2(probabilities[probabilities > 0]))
        return entropy


class BaselineDeviationDetector:
    """Detects deviations from behavioral baseline."""
    
    def __init__(self, baseline_engine):
        self.baseline_engine = baseline_engine
        
    def detect(self, flow_data: Dict, src_ip: str) -> AnomalyDetectionResult:
        """
        Detect anomalies based on baseline deviation.
        
        Args:
            flow_data: Flow data
            src_ip: Source IP address
            
        Returns:
            AnomalyDetectionResult
        """
        if not self.baseline_engine or not hasattr(self.baseline_engine, 'get_baseline'):
            return AnomalyDetectionResult(
                detector_type=AnomalyType.BASELINE_DEVIATION,
                score=0.0,
                is_anomalous=False,
                reason="Baseline engine not available",
                threshold=3.0
            )
        
        # Get baseline for source IP
        baseline = self.baseline_engine.get_baseline(src_ip)
        
        # Check bytes sent
        bytes_sent = flow_data.get('bytes_out', 0)
        is_anomalous, z_score = baseline.is_anomalous(bytes_sent, threshold_std=3.0) if baseline else (False, 0.0)
        
        anomaly_score = min(1.0, abs(z_score) / 4.0)
        
        return AnomalyDetectionResult(
            detector_type=AnomalyType.BASELINE_DEVIATION,
            score=anomaly_score,
            is_anomalous=is_anomalous,
            reason=f"Baseline deviation: {z_score:.2f} std from normal",
            threshold=3.0,
            raw_value=z_score
        )


class ZeroDayDetectionEngine:
    """
    Main zero-day detection engine.
    Orchestrates multiple anomaly detectors.
    """
    
    def __init__(self, autoencoder_model=None, baseline_engine=None, device: str = 'cpu'):
        """
        Initialize the zero-day detection engine.
        
        Args:
            autoencoder_model: Pre-trained autoencoder model
            baseline_engine: Baseline engine for behavioral analysis
            device: Device to use for models ('cpu' or 'cuda')
        """
        self.autoencoder_model = autoencoder_model
        self.baseline_engine = baseline_engine
        self.device = device
        
        # Initialize detectors
        self.reconstruction_detector = ReconstructionErrorDetector(threshold_percentile=95.0)
        self.statistical_detector = StatisticalAnomalyDetector(z_threshold=3.0)
        self.temporal_detector = TemporalAnomalyDetector(window_size=100)
        self.entropy_detector = EntropyAnomalyDetector(threshold=3.0)
        self.baseline_detector = BaselineDeviationDetector(baseline_engine)
        
        # Detector weights (tunable)
        self.weights = {
            AnomalyType.RECONSTRUCTION_ERROR: 0.25,
            AnomalyType.STATISTICAL: 0.20,
            AnomalyType.TEMPORAL_SPIKE: 0.15,
            AnomalyType.ENTROPY_ANOMALY: 0.15,
            AnomalyType.BASELINE_DEVIATION: 0.25,
        }
        
        # Detection cache for deduplication
        self.recent_detections = deque(maxlen=1000)
        
        logger.info("ZeroDayDetectionEngine initialized")
    
    def detect(self, flow_data: Dict, features: np.ndarray) -> ZeroDayDetectionResult:
        """
        Detect zero-day attacks in a single flow.
        
        Args:
            flow_data: Raw flow data dictionary
            features: Pre-processed feature vector (should be normalized)
            
        Returns:
            ZeroDayDetectionResult
        """
        results = []
        detector_scores = {}
        
        # 1. Reconstruction Error Detection
        try:
            if self.autoencoder_model is not None:
                features_tensor = torch.FloatTensor(features.reshape(1, -1)).to(self.device)
                with torch.no_grad():
                    output, _ = self.autoencoder_model(features_tensor)
                    output_np = output.cpu().numpy().flatten()
                
                result = self.reconstruction_detector.detect(features, output_np)
                results.append(result)
                detector_scores[AnomalyType.RECONSTRUCTION_ERROR.value] = result.score
        except Exception as e:
            logger.warning(f"Autoencoder detection failed: {e}")
        
        # 2. Statistical Anomaly Detection
        try:
            result = self.statistical_detector.detect(features)
            results.append(result)
            detector_scores[AnomalyType.STATISTICAL.value] = result.score
        except Exception as e:
            logger.warning(f"Statistical detection failed: {e}")
        
        # 3. Temporal Spike Detection
        try:
            bytes_sent = flow_data.get('bytes_out', 0)
            packet_count = flow_data.get('packets', 1)
            duration = flow_data.get('duration', 1)
            
            result = self.temporal_detector.detect(bytes_sent, packet_count, duration)
            results.append(result)
            detector_scores[AnomalyType.TEMPORAL_SPIKE.value] = result.score
        except Exception as e:
            logger.warning(f"Temporal detection failed: {e}")
        
        # 4. Entropy Anomaly Detection
        try:
            result = self.entropy_detector.detect(flow_data)
            results.append(result)
            detector_scores[AnomalyType.ENTROPY_ANOMALY.value] = result.score
        except Exception as e:
            logger.warning(f"Entropy detection failed: {e}")
        
        # 5. Baseline Deviation Detection
        try:
            src_ip = flow_data.get('src_ip', 'unknown')
            result = self.baseline_detector.detect(flow_data, src_ip)
            results.append(result)
            detector_scores[AnomalyType.BASELINE_DEVIATION.value] = result.score
        except Exception as e:
            logger.warning(f"Baseline detection failed: {e}")
        
        # Compute ensemble score
        ensemble_score = self._compute_ensemble_score(results)
        confidence = self._compute_confidence(results)
        
        # Determine if anomaly
        is_anomaly = ensemble_score > 0.5
        
        # Get primary detectors
        primary_detectors = [r.detector_type.value for r in results if r.is_anomalous]
        
        # Build reasoning
        reasoning = self._build_reasoning(results, ensemble_score, confidence)
        evidence = self._build_evidence(results, flow_data)
        
        # Guess anomaly type
        anomaly_type_guess = self._guess_anomaly_type(results, flow_data)
        
        # Get baseline deviation
        baseline_deviation_std = self._get_baseline_deviation(flow_data)
        
        return ZeroDayDetectionResult(
            is_anomaly=is_anomaly,
            anomaly_score=ensemble_score,
            confidence=confidence,
            detector_scores=detector_scores,
            detector_results=results,
            primary_detectors=primary_detectors,
            reasoning=reasoning,
            evidence=evidence,
            flow_key=f"{flow_data.get('src_ip')}→{flow_data.get('dst_ip')}",
            baseline_deviation_std=baseline_deviation_std,
            anomaly_type_guess=anomaly_type_guess
        )
    
    def _compute_ensemble_score(self, results: List[AnomalyDetectionResult]) -> float:
        """Compute weighted ensemble anomaly score."""
        if not results:
            return 0.0
        
        total_weight = 0.0
        weighted_score = 0.0
        
        for result in results:
            weight = self.weights.get(result.detector_type, 0.2)
            weighted_score += result.score * weight
            total_weight += weight
        
        if total_weight > 0:
            return min(1.0, weighted_score / total_weight)
        return 0.0
    
    def _compute_confidence(self, results: List[AnomalyDetectionResult]) -> float:
        """Compute confidence based on detector agreement."""
        if not results:
            return 0.0
        
        # Count anomalous detectors
        anomalous_count = sum(1 for r in results if r.is_anomalous)
        
        # Confidence based on agreement
        agreement_ratio = anomalous_count / len(results)
        
        # Get max score across detectors
        max_score = max((r.score for r in results), default=0.0)
        
        # Combine agreement and intensity
        confidence = (agreement_ratio * 0.5) + (max_score * 0.5)
        
        return min(1.0, confidence)
    
    def _build_reasoning(self, results: List[AnomalyDetectionResult], ensemble_score: float, confidence: float) -> str:
        """Build human-readable reasoning."""
        anomalous_results = [r for r in results if r.is_anomalous]
        
        if not anomalous_results:
            return f"No significant anomalies detected (score: {ensemble_score:.2f})"
        
        reasons = [r.reason for r in anomalous_results]
        return f"Ensemble Score: {ensemble_score:.2f} | Confidence: {confidence:.2f} | Detectors: {', '.join(reasons)}"
    
    def _build_evidence(self, results: List[AnomalyDetectionResult], flow_data: Dict) -> List[str]:
        """Build evidence list."""
        evidence = []
        
        for result in results:
            if result.is_anomalous:
                evidence.append(f"{result.detector_type.value}: {result.reason}")
        
        # Add contextual evidence
        if flow_data.get('dst_ip') in self._known_c2_servers():
            evidence.append("Connecting to known C2 server")
        
        return evidence
    
    def _guess_anomaly_type(self, results: List[AnomalyDetectionResult], flow_data: Dict) -> str:
        """Guess the type of anomaly."""
        if any(r.detector_type == AnomalyType.TEMPORAL_SPIKE and r.is_anomalous for r in results):
            bytes_out = flow_data.get('bytes_out', 0)
            if bytes_out > 1_000_000:  # > 1MB
                return "data_exfiltration"
            return "ddos"
        
        if any(r.detector_type == AnomalyType.ENTROPY_ANOMALY and r.is_anomalous for r in results):
            return "encrypted_malware"
        
        if any(r.detector_type == AnomalyType.BASELINE_DEVIATION and r.is_anomalous for r in results):
            return "behavioral_anomaly"
        
        return "unknown_zero_day"
    
    def _get_baseline_deviation(self, flow_data: Dict) -> float:
        """Get baseline deviation in standard deviations."""
        if self.baseline_engine:
            baseline = self.baseline_engine.get_baseline(flow_data.get('src_ip', 'unknown'))
            if baseline:
                bytes_sent = flow_data.get('bytes_out', 0)
                _, z_score = baseline.is_anomalous(bytes_sent)
                return abs(z_score)
        return 0.0
    
    @staticmethod
    def _known_c2_servers() -> set:
        """Return set of known C2 servers (would come from threat intelligence)."""
        # This would integrate with threat intelligence feeds
        return set()
    
    def update_weights(self, weights: Dict[str, float]):
        """Update detector weights dynamically."""
        for key, value in weights.items():
            try:
                anomaly_type = AnomalyType(key)
                self.weights[anomaly_type] = value
                logger.info(f"Updated weight for {key}: {value}")
            except ValueError:
                logger.warning(f"Unknown detector type: {key}")
    
    def get_detector_stats(self) -> Dict:
        """Get statistics about detectors."""
        return {
            'reconstruction_error_history_size': len(self.reconstruction_detector.error_history),
            'statistical_history_size': len(self.statistical_detector.feature_history),
            'temporal_history_size': len(self.temporal_detector.flow_rates),
            'entropy_history_size': len(self.entropy_detector.entropy_history),
            'recent_detections': len(self.recent_detections),
            'weights': {k.value: v for k, v in self.weights.items()}
        }
