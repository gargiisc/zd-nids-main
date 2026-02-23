"""
Multi-Model Anomaly Fusion Engine
==================================
Combines multiple anomaly detection approaches for robust zero-day detection.

Detects anomalies through:
- Unsupervised learning (Isolation Forest)
- Reconstruction-based (Autoencoder)
- Statistical methods (Z-score, MAD)
- Behavioral baselines
- Temporal patterns

Author: AI-NIDS Team
"""

import numpy as np
from sklearn.ensemble import IsolationForest
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class IsolationForestDetection:
    """Isolation Forest anomaly detection result."""
    score: float  # -1 to 1 (negative = normal, positive = anomaly)
    is_anomaly: bool
    contamination_level: float
    reason: str


class IsolationForestAnomalyDetector:
    """
    Isolation Forest-based anomaly detector.
    Isolates anomalies by randomly selecting features and split values.
    """
    
    def __init__(self, contamination: float = 0.01, n_estimators: int = 100):
        """
        Initialize Isolation Forest detector.
        
        Args:
            contamination: Expected proportion of anomalies (0-1)
            n_estimators: Number of isolation trees
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1  # Use all CPUs
        )
        self.is_fitted = False
        self.training_data = []
        
    def fit(self, X: np.ndarray):
        """
        Fit the Isolation Forest model.
        
        Args:
            X: Training data (n_samples, n_features)
        """
        try:
            self.model.fit(X)
            self.is_fitted = True
            self.training_data = X
            logger.info(f"Isolation Forest fitted with {len(X)} samples")
        except Exception as e:
            logger.error(f"Failed to fit Isolation Forest: {e}")
    
    def predict(self, X: np.ndarray) -> IsolationForestDetection:
        """
        Predict if sample is anomalous.
        
        Args:
            X: Sample(s) to predict (1D or 2D array)
            
        Returns:
            IsolationForestDetection
        """
        if not self.is_fitted:
            return IsolationForestDetection(
                score=0.0,
                is_anomaly=False,
                contamination_level=self.contamination,
                reason="Model not fitted yet"
            )
        
        # Handle single sample
        if X.ndim == 1:
            X = X.reshape(1, -1)
        
        try:
            # Get anomaly score (-1 = anomaly, 1 = normal)
            anomaly_labels = self.model.predict(X)
            scores = self.model.score_samples(X)
            
            # Convert to 0-1 range (higher = more anomalous)
            # Score ranges from -max_score to max_score
            # We map to 0-1 where 1 = most anomalous
            normalized_score = 1 / (1 + np.exp(-scores[0]))  # Sigmoid normalization
            
            is_anomaly = anomaly_labels[0] == -1
            
            reason = f"Isolation score: {scores[0]:.4f}, anomaly: {is_anomaly}"
            
            return IsolationForestDetection(
                score=float(normalized_score),
                is_anomaly=is_anomaly,
                contamination_level=self.contamination,
                reason=reason
            )
        except Exception as e:
            logger.error(f"Isolation Forest prediction failed: {e}")
            return IsolationForestDetection(
                score=0.0,
                is_anomaly=False,
                contamination_level=self.contamination,
                reason=f"Prediction error: {str(e)}"
            )
    
    def partial_fit(self, X: np.ndarray):
        """
        Incremental learning (note: sklearn IsolationForest doesn't support true partial_fit,
        so we retrain periodically).
        
        Args:
            X: New data to incorporate
        """
        self.training_data.append(X)
        
        # Retrain every 10000 samples
        if len(self.training_data) > 10000:
            combined_data = np.vstack(self.training_data[-10000:])
            self.fit(combined_data)


class MADOutlierDetector:
    """Median Absolute Deviation (MAD) based outlier detection."""
    
    def __init__(self, threshold_mad: float = 3.0):
        """
        Initialize MAD detector.
        
        Args:
            threshold_mad: Number of MADs for threshold
        """
        self.threshold_mad = threshold_mad
        self.feature_medians = None
        self.feature_mads = None
        self.feature_history = []
        
    def fit(self, X: np.ndarray):
        """Fit MAD parameters."""
        self.feature_history = X.tolist()
        X_array = np.array(self.feature_history)
        
        self.feature_medians = np.median(X_array, axis=0)
        deviations = np.abs(X_array - self.feature_medians)
        self.feature_mads = np.median(deviations, axis=0)
        
        logger.info(f"MAD detector fitted with {len(X)} samples")
    
    def predict(self, x: np.ndarray) -> Tuple[bool, float, str]:
        """
        Predict if sample is anomalous using MAD.
        
        Args:
            x: Single sample (1D array)
            
        Returns:
            Tuple of (is_anomaly, score, reason)
        """
        if self.feature_medians is None:
            return False, 0.0, "MAD detector not fitted"
        
        # Calculate deviations from median
        deviations = np.abs(x - self.feature_medians)
        
        # Avoid division by zero
        mad_array = np.where(self.feature_mads == 0, 1e-6, self.feature_mads)
        
        # Calculate modified Z-scores using MAD
        modified_z_scores = 0.6745 * deviations / mad_array
        
        max_z_score = np.max(modified_z_scores)
        is_anomaly = max_z_score > self.threshold_mad
        
        # Normalize score to 0-1
        score = min(1.0, max_z_score / (self.threshold_mad * 2))
        
        reason = f"MAD Z-score: {max_z_score:.2f} (threshold: {self.threshold_mad})"
        
        return is_anomaly, score, reason


class KernelDensityAnomalyDetector:
    """Kernel Density Estimation based anomaly detector."""
    
    def __init__(self, bandwidth: float = 0.1):
        """
        Initialize KDE detector.
        
        Args:
            bandwidth: Kernel bandwidth
        """
        self.bandwidth = bandwidth
        self.training_data = None
        self.density_threshold = None
        
    def fit(self, X: np.ndarray):
        """Fit KDE."""
        try:
            from sklearn.neighbors import KernelDensity
            self.kde = KernelDensity(bandwidth=self.bandwidth)
            self.kde.fit(X)
            self.training_data = X
            
            # Set threshold as bottom 5% percentile
            scores = self.kde.score_samples(X)
            self.density_threshold = np.percentile(scores, 5)
            
            logger.info(f"KDE detector fitted with {len(X)} samples")
        except ImportError:
            logger.warning("sklearn not available for KDE")
    
    def predict(self, x: np.ndarray) -> Tuple[bool, float, str]:
        """Predict using KDE."""
        if not hasattr(self, 'kde'):
            return False, 0.0, "KDE detector not fitted"
        
        try:
            score = self.kde.score_samples(x.reshape(1, -1))[0]
            is_anomaly = score < self.density_threshold
            
            # Normalize to 0-1 (invert because lower density = more anomalous)
            normalized_score = min(1.0, max(0.0, 1 - (score / self.density_threshold)))
            
            reason = f"KDE density: {score:.4f} (threshold: {self.density_threshold:.4f})"
            
            return is_anomaly, normalized_score, reason
        except Exception as e:
            logger.error(f"KDE prediction failed: {e}")
            return False, 0.0, f"KDE error: {str(e)}"


class LocalOutlierFactorDetector:
    """Local Outlier Factor (LOF) based anomaly detector."""
    
    def __init__(self, n_neighbors: int = 20):
        """
        Initialize LOF detector.
        
        Args:
            n_neighbors: Number of neighbors for LOF
        """
        self.n_neighbors = n_neighbors
        self.lof = None
        self.threshold = None
        
    def fit(self, X: np.ndarray):
        """Fit LOF."""
        try:
            from sklearn.neighbors import LocalOutlierFactor
            self.lof = LocalOutlierFactor(
                n_neighbors=self.n_neighbors,
                novelty=True
            )
            self.lof.fit(X)
            
            # Get scores for training data
            lof_scores = self.lof.negative_outlier_factor_
            self.threshold = np.percentile(lof_scores, 5)
            
            logger.info(f"LOF detector fitted with {len(X)} samples")
        except ImportError:
            logger.warning("sklearn not available for LOF")
    
    def predict(self, x: np.ndarray) -> Tuple[bool, float, str]:
        """Predict using LOF."""
        if self.lof is None:
            return False, 0.0, "LOF detector not fitted"
        
        try:
            score = self.lof.predict(x.reshape(1, -1))[0]
            lof_score = self.lof.negative_outlier_factor_[0] if hasattr(self.lof, 'negative_outlier_factor_') else 0
            
            is_anomaly = score == -1  # -1 = outlier
            
            # Normalize score
            normalized_score = 0.5 if is_anomaly else 0.3
            
            reason = f"LOF: {'anomaly' if is_anomaly else 'normal'}"
            
            return is_anomaly, normalized_score, reason
        except Exception as e:
            logger.error(f"LOF prediction failed: {e}")
            return False, 0.0, f"LOF error: {str(e)}"


class AnomalyFusionEngine:
    """
    Multi-model anomaly fusion engine.
    Combines multiple anomaly detectors for robust zero-day detection.
    """
    
    def __init__(self):
        """Initialize the fusion engine."""
        self.isolation_forest = IsolationForestAnomalyDetector(contamination=0.01)
        self.mad_detector = MADOutlierDetector(threshold_mad=3.0)
        self.kde_detector = KernelDensityAnomalyDetector(bandwidth=0.1)
        self.lof_detector = LocalOutlierFactorDetector(n_neighbors=20)
        
        # Fusion weights
        self.weights = {
            'isolation_forest': 0.35,
            'mad': 0.25,
            'kde': 0.20,
            'lof': 0.20,
        }
        
        self.is_fitted = False
        
    def fit(self, X: np.ndarray):
        """
        Fit all detectors.
        
        Args:
            X: Training data
        """
        try:
            self.isolation_forest.fit(X)
            self.mad_detector.fit(X)
            self.kde_detector.fit(X)
            self.lof_detector.fit(X)
            self.is_fitted = True
            logger.info(f"Anomaly Fusion Engine fitted with {len(X)} samples")
        except Exception as e:
            logger.error(f"Failed to fit fusion engine: {e}")
    
    def predict(self, x: np.ndarray) -> Dict:
        """
        Predict anomaly score using ensemble of detectors.
        
        Args:
            x: Sample to predict (1D array)
            
        Returns:
            Dictionary with:
            - 'is_anomaly': bool
            - 'anomaly_score': 0-1 float
            - 'confidence': 0-1 float
            - 'detector_scores': dict of individual scores
            - 'reasoning': str
        """
        if not self.is_fitted:
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'detector_scores': {},
                'reasoning': 'Fusion engine not fitted'
            }
        
        detector_scores = {}
        detector_reasons = []
        anomaly_count = 0
        
        # 1. Isolation Forest
        if_result = self.isolation_forest.predict(x)
        detector_scores['isolation_forest'] = if_result.score
        detector_reasons.append(f"IF: {if_result.reason}")
        if if_result.is_anomaly:
            anomaly_count += 1
        
        # 2. MAD
        mad_is_anomaly, mad_score, mad_reason = self.mad_detector.predict(x)
        detector_scores['mad'] = mad_score
        detector_reasons.append(f"MAD: {mad_reason}")
        if mad_is_anomaly:
            anomaly_count += 1
        
        # 3. KDE
        kde_is_anomaly, kde_score, kde_reason = self.kde_detector.predict(x)
        detector_scores['kde'] = kde_score
        detector_reasons.append(f"KDE: {kde_reason}")
        if kde_is_anomaly:
            anomaly_count += 1
        
        # 4. LOF
        lof_is_anomaly, lof_score, lof_reason = self.lof_detector.predict(x)
        detector_scores['lof'] = lof_score
        detector_reasons.append(f"LOF: {lof_reason}")
        if lof_is_anomaly:
            anomaly_count += 1
        
        # Compute weighted ensemble score
        ensemble_score = (
            self.weights['isolation_forest'] * detector_scores['isolation_forest'] +
            self.weights['mad'] * detector_scores['mad'] +
            self.weights['kde'] * detector_scores['kde'] +
            self.weights['lof'] * detector_scores['lof']
        )
        
        # Confidence based on detector agreement
        detector_agreement = anomaly_count / 4.0  # 0-1
        confidence = (detector_agreement * 0.5) + (ensemble_score * 0.5)
        
        is_anomaly = ensemble_score > 0.5
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': float(ensemble_score),
            'confidence': float(confidence),
            'detector_scores': detector_scores,
            'detector_agreement': anomaly_count / 4.0,
            'reasoning': ' | '.join(detector_reasons)
        }
    
    def update_weights(self, weights: Dict[str, float]):
        """
        Update fusion weights.
        
        Args:
            weights: Dictionary with detector names as keys
        """
        for key, value in weights.items():
            if key in self.weights:
                self.weights[key] = value
                logger.info(f"Updated weight for {key}: {value}")
    
    def get_detector_status(self) -> Dict:
        """Get status of all detectors."""
        return {
            'fusion_engine_fitted': self.is_fitted,
            'isolation_forest_fitted': self.isolation_forest.is_fitted,
            'mad_fitted': self.mad_detector.feature_medians is not None,
            'weights': self.weights
        }
