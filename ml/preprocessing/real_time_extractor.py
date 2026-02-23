"""
Real-Time Feature Extraction Pipeline
====================================
Fast, streaming feature extraction for <2ms per flow latency.

Optimizations:
- Pre-computed lookups
- Vectorized NumPy operations
- Minimal memory allocation
- GPU-ready tensors

Author: AI-NIDS Team
"""

import numpy as np
import logging
from typing import Dict, List, Optional, Tuple
from functools import lru_cache
from datetime import datetime

logger = logging.getLogger(__name__)


class FeatureCache:
    """Cache for frequently accessed features."""
    
    def __init__(self):
        """Initialize feature cache."""
        self.port_risk_scores = self._init_port_risk_scores()
        self.protocol_codes = self._init_protocol_codes()
        self.feature_mins = None
        self.feature_maxs = None
        self.feature_means = None
        self.feature_stds = None
    
    @staticmethod
    def _init_port_risk_scores() -> Dict[int, float]:
        """Initialize port risk scoring."""
        return {
            # Low risk (common services)
            80: 0.1, 443: 0.1, 22: 0.2, 21: 0.2,
            53: 0.1, 25: 0.2, 110: 0.2, 143: 0.2,
            3306: 0.3, 5432: 0.3, 6379: 0.3,
            
            # Medium risk
            445: 0.5, 139: 0.5, 135: 0.5,
            3389: 0.6, 5900: 0.6,
            
            # High risk (uncommon/malware ports)
            4444: 0.9, 5555: 0.9, 6666: 0.9, 7777: 0.9,
            8888: 0.8, 9999: 0.8,
        }
    
    @staticmethod
    def _init_protocol_codes() -> Dict[str, float]:
        """Initialize protocol numeric encoding."""
        return {
            'TCP': 1.0,
            'UDP': 2.0,
            'ICMP': 3.0,
            'DNS': 4.0,
            'TLS': 5.0,
            'SSH': 6.0,
            'HTTP': 7.0,
            'HTTPS': 8.0,
            'FTP': 9.0,
            'SMTP': 10.0,
            'POP3': 11.0,
            'IMAP': 12.0,
        }
    
    def get_port_risk(self, port: int) -> float:
        """Get risk score for port."""
        return self.port_risk_scores.get(port, 0.4)  # Default: medium risk
    
    def get_protocol_code(self, protocol: str) -> float:
        """Get numeric code for protocol."""
        return self.protocol_codes.get(protocol.upper(), 0.0)
    
    def set_normalization_params(self, mins: np.ndarray, maxs: np.ndarray, 
                                 means: np.ndarray, stds: np.ndarray):
        """Set feature normalization parameters."""
        self.feature_mins = mins
        self.feature_maxs = maxs
        self.feature_means = means
        self.feature_stds = stds


class RealtimeFeatureExtractor:
    """
    Extracts features from a single flow in <2ms.
    Optimized for streaming inference.
    """
    
    # Feature list (must match training data)
    FEATURE_NAMES = [
        # Basic flow info
        'src_ip_encoded', 'dst_ip_encoded', 'src_port', 'dst_port',
        'protocol_code',
        
        # Packet statistics
        'bytes_in', 'bytes_out', 'packets_in', 'packets_out',
        'bytes_per_packet', 'packets_per_second',
        
        # Flow statistics
        'duration', 'avg_packet_size', 'packet_variance',
        'inter_packet_gap', 'packet_gap_variance',
        
        # Protocol-specific
        'tcp_flags_syn', 'tcp_flags_ack', 'tcp_flags_fin', 'tcp_flags_rst',
        'tcp_flags_psh', 'tcp_flags_urg',
        
        # Payload analysis
        'payload_entropy', 'payload_size', 'payload_variance',
        'null_byte_ratio', 'printable_char_ratio',
        
        # Flow characteristics
        'port_risk_score', 'is_internal_dst', 'is_internal_src',
        'is_broadcast', 'is_multicast',
        
        # Window/rate statistics
        'bytes_out_rate', 'packets_out_rate',
        'flow_duration_normalized',
        
        # Derived features
        'protocol_anomaly_score', 'port_combination_risk',
        'byte_distribution_entropy',
    ]
    
    def __init__(self, cache: Optional[FeatureCache] = None):
        """
        Initialize feature extractor.
        
        Args:
            cache: Feature cache object
        """
        self.cache = cache or FeatureCache()
        self.feature_count = len(self.FEATURE_NAMES)
    
    def extract(self, flow_data: Dict) -> np.ndarray:
        """
        Extract features from a single flow.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Numpy array of features
        """
        features = np.zeros(self.feature_count, dtype=np.float32)
        
        # 1. Basic flow info
        features[0] = self._encode_ip(flow_data.get('src_ip', '0.0.0.0'))
        features[1] = self._encode_ip(flow_data.get('dst_ip', '0.0.0.0'))
        features[2] = float(flow_data.get('src_port', 0))
        features[3] = float(flow_data.get('dst_port', 0))
        features[4] = self.cache.get_protocol_code(flow_data.get('protocol', 'TCP'))
        
        # 2. Packet statistics
        bytes_in = float(flow_data.get('bytes_in', 0))
        bytes_out = float(flow_data.get('bytes_out', 0))
        packets_in = float(flow_data.get('packets_in', 1))
        packets_out = float(flow_data.get('packets_out', 1))
        
        features[5] = bytes_in
        features[6] = bytes_out
        features[7] = packets_in
        features[8] = packets_out
        
        # 3. Derived packet stats
        total_packets = packets_in + packets_out
        total_bytes = bytes_in + bytes_out
        
        features[9] = total_bytes / max(1, total_packets)  # bytes_per_packet
        
        duration = max(0.001, float(flow_data.get('duration', 1)))
        features[10] = total_packets / duration  # packets_per_second
        
        # 4. Flow statistics
        features[11] = duration
        features[12] = total_bytes / max(1, total_packets)  # avg_packet_size
        features[13] = self._compute_packet_variance(flow_data)
        features[14] = duration / max(1, total_packets)  # inter_packet_gap
        features[15] = 0.0  # packet_gap_variance (would need packet timestamps)
        
        # 5. TCP flags
        flags = flow_data.get('tcp_flags', '')
        features[16] = 1.0 if 'S' in flags else 0.0
        features[17] = 1.0 if 'A' in flags else 0.0
        features[18] = 1.0 if 'F' in flags else 0.0
        features[19] = 1.0 if 'R' in flags else 0.0
        features[20] = 1.0 if 'P' in flags else 0.0
        features[21] = 1.0 if 'U' in flags else 0.0
        
        # 6. Payload analysis
        payload = flow_data.get('payload', b'')
        if isinstance(payload, str):
            payload = payload.encode()
        
        features[22] = self._calculate_entropy(payload)  # entropy
        features[23] = float(len(payload))  # payload_size
        features[24] = 0.0  # payload_variance
        features[25] = self._calculate_null_byte_ratio(payload)
        features[26] = self._calculate_printable_char_ratio(payload)
        
        # 7. Port and IP characteristics
        dst_port = int(flow_data.get('dst_port', 0))
        features[27] = self.cache.get_port_risk(dst_port)
        features[28] = 1.0 if self._is_internal_ip(flow_data.get('dst_ip', '')) else 0.0
        features[29] = 1.0 if self._is_internal_ip(flow_data.get('src_ip', '')) else 0.0
        features[30] = 1.0 if flow_data.get('is_broadcast', False) else 0.0
        features[31] = 1.0 if flow_data.get('is_multicast', False) else 0.0
        
        # 8. Rate statistics
        features[32] = bytes_out / duration  # bytes_out_rate
        features[33] = packets_out / duration  # packets_out_rate
        features[34] = min(1.0, duration / 3600.0)  # flow_duration_normalized
        
        # 9. Derived anomaly features
        features[35] = self._compute_protocol_anomaly(flow_data)
        features[36] = self._compute_port_combo_risk(flow_data)
        features[37] = self._calculate_entropy(bytes_out.to_bytes(8, 'big'))
        
        return features
    
    def extract_batch(self, flows: List[Dict]) -> np.ndarray:
        """
        Extract features from multiple flows.
        
        Args:
            flows: List of flow data dictionaries
            
        Returns:
            Numpy array of shape (n_flows, n_features)
        """
        features_list = [self.extract(flow) for flow in flows]
        return np.vstack(features_list)
    
    def normalize(self, features: np.ndarray) -> np.ndarray:
        """
        Normalize features using pre-computed statistics.
        
        Args:
            features: Feature array
            
        Returns:
            Normalized features
        """
        if (self.cache.feature_means is None or 
            self.cache.feature_stds is None):
            logger.warning("Normalization parameters not set, returning unnormalized features")
            return features
        
        # Z-score normalization
        normalized = (features - self.cache.feature_means) / (self.cache.feature_stds + 1e-6)
        
        return normalized.astype(np.float32)
    
    @staticmethod
    def _encode_ip(ip: str) -> float:
        """
        Encode IP address as float.
        Simple hash encoding for speed.
        """
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) == 4:
                return float((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
        except (ValueError, IndexError):
            pass
        return 0.0
    
    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        """Check if IP is internal."""
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False
            
            first = parts[0]
            
            # 10.0.0.0/8
            if first == 10:
                return True
            
            # 172.16.0.0/12
            if first == 172 and 16 <= parts[1] <= 31:
                return True
            
            # 192.168.0.0/16
            if first == 192 and parts[1] == 168:
                return True
            
            # 127.0.0.0/8
            if first == 127:
                return True
            
            return False
        except (ValueError, IndexError):
            return False
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        entropy = -np.sum(probabilities[probabilities > 0] * np.log2(probabilities[probabilities > 0]))
        
        return float(entropy)
    
    @staticmethod
    def _calculate_null_byte_ratio(data: bytes) -> float:
        """Calculate ratio of null bytes."""
        if not data:
            return 0.0
        return float(data.count(0) / len(data))
    
    @staticmethod
    def _calculate_printable_char_ratio(data: bytes) -> float:
        """Calculate ratio of printable characters."""
        if not data:
            return 0.0
        
        printable_count = sum(
            1 for b in data if 32 <= b <= 126 or b in (9, 10, 13)
        )
        return float(printable_count / len(data))
    
    @staticmethod
    def _compute_packet_variance(flow_data: Dict) -> float:
        """Compute packet size variance."""
        # Simplified - would need packet-level data
        return 0.0
    
    @staticmethod
    def _compute_protocol_anomaly(flow_data: Dict) -> float:
        """Compute protocol-level anomaly score."""
        protocol = flow_data.get('protocol', 'TCP').upper()
        dst_port = int(flow_data.get('dst_port', 0))
        
        # Check port/protocol mismatch
        protocol_ports = {
            'TCP': [80, 443, 22, 21, 25, 110, 143, 3306, 5432],
            'UDP': [53, 123, 161, 5060],
            'ICMP': [],
        }
        
        if protocol in protocol_ports:
            expected_ports = protocol_ports[protocol]
            if dst_port not in expected_ports and dst_port > 1024:
                return 0.5  # Suspicious
        
        return 0.0
    
    @staticmethod
    def _compute_port_combo_risk(flow_data: Dict) -> float:
        """Compute risk of source/destination port combination."""
        src_port = int(flow_data.get('src_port', 0))
        dst_port = int(flow_data.get('dst_port', 0))
        
        # High-risk combinations
        if src_port in [53, 123, 161] and dst_port > 1024:
            return 0.8  # DNS/NTP amplification
        
        if src_port == 0:
            return 0.6  # Invalid source port
        
        return 0.0


class StreamingFeatureNormalizer:
    """Normalizes features for streaming inference."""
    
    def __init__(self, feature_count: int):
        """Initialize normalizer."""
        self.feature_count = feature_count
        self.means = np.zeros(feature_count, dtype=np.float32)
        self.stds = np.ones(feature_count, dtype=np.float32)
        self.is_fitted = False
    
    def fit(self, X: np.ndarray):
        """Fit normalization parameters."""
        self.means = np.mean(X, axis=0)
        self.stds = np.std(X, axis=0)
        self.stds = np.where(self.stds == 0, 1e-6, self.stds)
        self.is_fitted = True
        logger.info(f"Normalizer fitted on {X.shape[0]} samples")
    
    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform features."""
        if not self.is_fitted:
            logger.warning("Normalizer not fitted, returning unnormalized features")
            return X
        
        return (X - self.means) / self.stds
    
    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit and transform."""
        self.fit(X)
        return self.transform(X)
