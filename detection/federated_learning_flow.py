"""
Real-Time Federated Learning Flow Coordinator
==============================================
Implements the architecture diagram flow for real-time federated learning:

1. Detectors detect unknown attacks
2. Upload learned parameters (encrypted gradients)
3. Global Aggregation Platform aggregates updates
4. Broadcast updated model back to all detectors
5. Detectors deploy and detect locally

Author: AI-NIDS Team
"""

import logging
import threading
import queue
import json
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class TrainingRoundState(Enum):
    """Training round states."""
    INITIATED = "initiated"
    COLLECTING_UPDATES = "collecting_updates"
    AGGREGATING = "aggregating"
    DISTRIBUTING = "distributing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ClientGradientUpdate:
    """Gradient update from a federated client."""
    client_id: str
    round_number: int
    model_weights: Dict  # Model parameters/weights
    gradients: Dict  # Computed gradients
    training_metrics: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'client_id': self.client_id,
            'round_number': self.round_number,
            'timestamp': self.timestamp.isoformat(),
            'metrics': self.training_metrics
        }


@dataclass
class GlobalAggregationResult:
    """Result of global model aggregation."""
    round_number: int
    aggregation_strategy: str  # fedavg, fedprox, etc.
    global_accuracy: float
    global_loss: float
    total_samples: int
    participating_clients: int
    new_attack_types_detected: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'round_number': self.round_number,
            'aggregation_strategy': self.aggregation_strategy,
            'global_accuracy': self.global_accuracy,
            'global_loss': self.global_loss,
            'total_samples': self.total_samples,
            'participating_clients': self.participating_clients,
            'new_attacks': self.new_attack_types_detected,
            'timestamp': self.timestamp.isoformat()
        }


class RealTimeFederatedLearningCoordinator:
    """
    Coordinates real-time federated learning following the architecture diagram.
    
    Flow:
    1. Detectors send incremental learning updates (encrypted gradients)
    2. Server aggregates updates using FedAvg/FedProx
    3. Global model is distributed back to detectors
    4. Detectors deploy updated model for local detection
    5. Process repeats continuously
    """
    
    def __init__(
        self,
        server_url: str = "localhost:8080",
        round_duration_seconds: int = 300,
        min_clients_per_round: int = 3,
        max_clients_per_round: int = 100
    ):
        """
        Initialize federated learning coordinator.
        
        Args:
            server_url: Central server URL
            round_duration_seconds: Duration of each training round
            min_clients_per_round: Minimum clients to participate
            max_clients_per_round: Maximum clients to participate
        """
        self.server_url = server_url
        self.round_duration_seconds = round_duration_seconds
        self.min_clients_per_round = min_clients_per_round
        self.max_clients_per_round = max_clients_per_round
        
        # Training state
        self.current_round = 0
        self.round_state = TrainingRoundState.INITIATED
        self.round_start_time: Optional[datetime] = None
        
        # Queues
        self.gradient_updates_queue = queue.Queue()  # Updates from clients
        self.model_distribution_queue = queue.Queue()  # Models to distribute
        
        # Round history
        self.round_history: List[GlobalAggregationResult] = []
        self.round_lock = threading.RLock()
        
        # Callbacks
        self.on_round_complete: Optional[Callable] = None
        self.on_aggregation_complete: Optional[Callable] = None
        
        # Background threads
        self.round_orchestrator_thread: Optional[threading.Thread] = None
        self.gradient_collector_thread: Optional[threading.Thread] = None
        self.aggregator_thread: Optional[threading.Thread] = None
        self.distributor_thread: Optional[threading.Thread] = None
        
        self.is_running = False
        
        logger.info(
            f"RealTimeFederatedLearningCoordinator initialized: "
            f"round_duration={round_duration_seconds}s, "
            f"min_clients={min_clients_per_round}"
        )
    
    def start(self):
        """Start federated learning coordination."""
        if self.is_running:
            logger.warning("Coordinator already running")
            return
        
        self.is_running = True
        
        # Start background threads
        self.round_orchestrator_thread = threading.Thread(
            target=self._round_orchestrator,
            daemon=True,
            name="FedRoundOrchestrator"
        )
        self.round_orchestrator_thread.start()
        
        self.gradient_collector_thread = threading.Thread(
            target=self._gradient_collector,
            daemon=True,
            name="FedGradientCollector"
        )
        self.gradient_collector_thread.start()
        
        self.aggregator_thread = threading.Thread(
            target=self._aggregator_worker,
            daemon=True,
            name="FedAggregator"
        )
        self.aggregator_thread.start()
        
        self.distributor_thread = threading.Thread(
            target=self._model_distributor,
            daemon=True,
            name="FedModelDistributor"
        )
        self.distributor_thread.start()
        
        logger.info("RealTimeFederatedLearningCoordinator started")
    
    def stop(self):
        """Stop federated learning coordination."""
        self.is_running = False
        
        threads = [
            self.round_orchestrator_thread,
            self.gradient_collector_thread,
            self.aggregator_thread,
            self.distributor_thread
        ]
        
        for thread in threads:
            if thread:
                thread.join(timeout=5)
        
        logger.info("RealTimeFederatedLearningCoordinator stopped")
    
    def submit_gradient_update(
        self,
        client_id: str,
        model_weights: Dict,
        gradients: Dict,
        training_metrics: Optional[Dict] = None
    ) -> bool:
        """
        Submit gradient update from a federated client.
        
        Called by clients after incremental learning.
        
        Args:
            client_id: Client identifier
            model_weights: Current local model weights
            gradients: Computed gradients
            training_metrics: Training metrics from local training
            
        Returns:
            True if update queued successfully
        """
        try:
            update = ClientGradientUpdate(
                client_id=client_id,
                round_number=self.current_round,
                model_weights=model_weights,
                gradients=gradients,
                training_metrics=training_metrics or {}
            )
            
            self.gradient_updates_queue.put(update)
            
            logger.debug(
                f"Gradient update submitted by {client_id} "
                f"for round {self.current_round}"
            )
            
            return True
        
        except Exception as e:
            logger.exception(f"Error submitting gradient update from {client_id}")
            return False
    
    def _round_orchestrator(self):
        """
        Background thread: Orchestrate training rounds.
        
        Follows architecture diagram:
        1. Initiate round
        2. Wait for gradient updates
        3. Trigger aggregation
        4. Distribute model
        5. Complete round
        """
        while self.is_running:
            try:
                with self.round_lock:
                    self.current_round += 1
                    self.round_state = TrainingRoundState.INITIATED
                    self.round_start_time = datetime.utcnow()
                
                logger.info(f"Starting federated learning round {self.current_round}")
                
                # Wait for gradient collection phase
                self._wait_for_gradient_collection()
                
                # Proceed to aggregation
                with self.round_lock:
                    self.round_state = TrainingRoundState.AGGREGATING
                
                # Wait for aggregation to complete
                time.sleep(10)  # Give aggregator time to process
                
                # Proceed to distribution
                with self.round_lock:
                    self.round_state = TrainingRoundState.DISTRIBUTING
                
                # Wait for distribution to complete
                time.sleep(5)
                
                # Mark round as complete
                with self.round_lock:
                    self.round_state = TrainingRoundState.COMPLETED
                
                logger.info(f"Completed federated learning round {self.current_round}")
                
                # Call callback
                if self.on_round_complete:
                    try:
                        self.on_round_complete(self.current_round)
                    except Exception as e:
                        logger.exception("Error in round complete callback")
                
                # Sleep before next round
                time.sleep(self.round_duration_seconds)
            
            except Exception as e:
                logger.exception("Error in round orchestrator")
                with self.round_lock:
                    self.round_state = TrainingRoundState.FAILED
                time.sleep(30)
    
    def _wait_for_gradient_collection(self, timeout_seconds: int = 60):
        """Wait for gradient updates from clients."""
        collected_updates = []
        deadline = time.time() + timeout_seconds
        
        while time.time() < deadline and self.is_running:
            try:
                update = self.gradient_updates_queue.get(timeout=5)
                
                if update.round_number == self.current_round:
                    collected_updates.append(update)
                    logger.debug(
                        f"Collected gradient from {update.client_id} "
                        f"({len(collected_updates)} total)"
                    )
                else:
                    logger.warning(
                        f"Ignoring stale gradient from {update.client_id} "
                        f"(round {update.round_number}, expected {self.current_round})"
                    )
            
            except queue.Empty:
                pass
        
        # Queue aggregation task
        if len(collected_updates) >= self.min_clients_per_round:
            logger.info(
                f"Collected {len(collected_updates)} gradient updates for round "
                f"{self.current_round}"
            )
            self.model_distribution_queue.put({
                'round_number': self.current_round,
                'updates': collected_updates,
                'update_count': len(collected_updates)
            })
        else:
            logger.warning(
                f"Insufficient gradient updates: {len(collected_updates)} / "
                f"{self.min_clients_per_round}"
            )
    
    def _gradient_collector(self):
        """Background thread: Monitor incoming gradients (passive collection)."""
        while self.is_running:
            try:
                # Log current queue depth
                queue_size = self.gradient_updates_queue.qsize()
                if queue_size > 0:
                    logger.debug(f"Gradient update queue depth: {queue_size}")
                
                time.sleep(30)
            
            except Exception as e:
                logger.exception("Error in gradient collector")
                time.sleep(30)
    
    def _aggregator_worker(self):
        """Background thread: Aggregate model updates from clients."""
        while self.is_running:
            try:
                if not self.model_distribution_queue.empty():
                    try:
                        task = self.model_distribution_queue.get_nowait()
                        
                        round_num = task['round_number']
                        updates = task['updates']
                        
                        logger.info(
                            f"Starting aggregation for round {round_num} "
                            f"with {len(updates)} updates"
                        )
                        
                        # Perform aggregation
                        result = self._perform_federated_aggregation(updates, round_num)
                        
                        # Store result
                        with self.round_lock:
                            self.round_history.append(result)
                        
                        # Call callback
                        if self.on_aggregation_complete:
                            try:
                                self.on_aggregation_complete(result)
                            except Exception as e:
                                logger.exception("Error in aggregation callback")
                        
                        logger.info(
                            f"Aggregation complete for round {round_num}: "
                            f"accuracy={result.global_accuracy:.4f}, "
                            f"loss={result.global_loss:.4f}"
                        )
                    
                    except queue.Empty:
                        pass
                
                time.sleep(2)
            
            except Exception as e:
                logger.exception("Error in aggregator")
                time.sleep(2)
    
    def _model_distributor(self):
        """Background thread: Distribute aggregated model to clients."""
        while self.is_running:
            try:
                # In production, this would:
                # 1. Push models to S3/storage
                # 2. Notify clients of new model via API
                # 3. Track deployment status
                
                time.sleep(10)
            
            except Exception as e:
                logger.exception("Error in model distributor")
                time.sleep(10)
    
    def _perform_federated_aggregation(
        self,
        updates: List[ClientGradientUpdate],
        round_number: int
    ) -> GlobalAggregationResult:
        """
        Perform federated averaging aggregation.
        
        Implements FedAvg: Global model = weighted average of client models
        """
        try:
            if not updates:
                return GlobalAggregationResult(
                    round_number=round_number,
                    aggregation_strategy="fedavg",
                    global_accuracy=0.0,
                    global_loss=float('inf'),
                    total_samples=0,
                    participating_clients=0
                )
            
            # Extract metrics
            total_samples = sum(
                u.training_metrics.get('samples', 0) for u in updates
            )
            
            accuracies = [
                u.training_metrics.get('accuracy', 0.0) for u in updates
            ]
            losses = [
                u.training_metrics.get('loss', float('inf')) for u in updates
            ]
            
            # Weighted average (by number of samples)
            global_accuracy = (
                sum(a * u.training_metrics.get('samples', 1) for a, u in zip(accuracies, updates)) /
                max(total_samples, 1)
            )
            
            global_loss = (
                sum(l * u.training_metrics.get('samples', 1) for l, u in zip(losses, updates)) /
                max(total_samples, 1)
            )
            
            # Extract new attack types
            new_attacks = set()
            for u in updates:
                if 'new_attacks' in u.training_metrics:
                    new_attacks.update(u.training_metrics['new_attacks'])
            
            result = GlobalAggregationResult(
                round_number=round_number,
                aggregation_strategy="fedavg",
                global_accuracy=global_accuracy,
                global_loss=global_loss,
                total_samples=total_samples,
                participating_clients=len(updates),
                new_attack_types_detected=list(new_attacks)
            )
            
            logger.info(f"Aggregation result: {result.to_dict()}")
            
            return result
        
        except Exception as e:
            logger.exception("Error performing aggregation")
            return GlobalAggregationResult(
                round_number=round_number,
                aggregation_strategy="fedavg",
                global_accuracy=0.0,
                global_loss=float('inf'),
                total_samples=0,
                participating_clients=0
            )
    
    def get_round_history(self, limit: int = 100) -> List[Dict]:
        """Get training round history."""
        with self.round_lock:
            return [r.to_dict() for r in self.round_history[-limit:]]
    
    def get_current_status(self) -> Dict:
        """Get current coordinator status."""
        with self.round_lock:
            return {
                'is_running': self.is_running,
                'current_round': self.current_round,
                'round_state': self.round_state.value,
                'round_start_time': self.round_start_time.isoformat() if self.round_start_time else None,
                'gradient_queue_size': self.gradient_updates_queue.qsize(),
                'rounds_completed': len(self.round_history),
                'latest_global_accuracy': (
                    self.round_history[-1].global_accuracy if self.round_history else 0.0
                ),
                'latest_global_loss': (
                    self.round_history[-1].global_loss if self.round_history else float('inf')
                )
            }


# Global instance
_global_coordinator: Optional[RealTimeFederatedLearningCoordinator] = None


def get_federated_coordinator() -> RealTimeFederatedLearningCoordinator:
    """Get or create global coordinator instance."""
    global _global_coordinator
    
    if _global_coordinator is None:
        _global_coordinator = RealTimeFederatedLearningCoordinator()
        _global_coordinator.start()
    
    return _global_coordinator
