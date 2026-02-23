"""
Federated Client Manager
========================
Manages federated learning clients with real-time synchronization.
Handles client registration, heartbeat monitoring, and global model distribution.

Follows the architecture diagram:
- Detectors register with server
- Upload learned parameters after incremental learning
- Receive updated global model
- Deploy and detect anomalies in real-time
"""

import logging
import threading
import queue
import json
import hashlib
import secrets
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class ClientStatus(Enum):
    """Client status enum."""
    REGISTERED = "registered"
    ONLINE = "online"
    OFFLINE = "offline"
    TRAINING = "training"
    SYNCING = "syncing"
    ERROR = "error"


@dataclass
class ClientHeartbeat:
    """Client heartbeat information."""
    client_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    flows_processed: int = 0
    attacks_detected: int = 0
    model_version: Optional[str] = None
    local_accuracy: Optional[float] = None
    status: ClientStatus = ClientStatus.ONLINE
    
    def to_dict(self) -> Dict:
        return {
            'client_id': self.client_id,
            'timestamp': self.timestamp.isoformat(),
            'flows_processed': self.flows_processed,
            'attacks_detected': self.attacks_detected,
            'model_version': self.model_version,
            'local_accuracy': self.local_accuracy,
            'status': self.status.value
        }


class FederatedClientManager:
    """
    Manages federated learning clients.
    
    Responsibilities:
    - Register/deregister clients
    - Monitor client heartbeats
    - Distribute global models
    - Collect training updates
    - Coordinate training rounds
    """
    
    def __init__(self, server_url: str = "localhost:8080"):
        """
        Initialize client manager.
        
        Args:
            server_url: Central server URL for client communication
        """
        self.server_url = server_url
        self.clients: Dict[str, ClientInfo] = {}
        self.client_lock = threading.RLock()
        
        # Heartbeat monitoring
        self.heartbeat_timeout_seconds = 300  # 5 minutes
        self.heartbeats: Dict[str, ClientHeartbeat] = {}
        self.heartbeat_history: Dict[str, List[ClientHeartbeat]] = {}
        
        # Training coordination
        self.current_round: int = 0
        self.training_rounds_history: List[Dict] = []
        
        # Event queues
        self.client_events = queue.Queue()  # For async client operations
        self.model_update_queue = queue.Queue()  # For model updates
        
        # Background threads
        self.heartbeat_monitor_thread: Optional[threading.Thread] = None
        self.model_distributor_thread: Optional[threading.Thread] = None
        self.is_running = False
        
        logger.info(f"FederatedClientManager initialized for server: {server_url}")
    
    def start(self):
        """Start background monitoring threads."""
        if self.is_running:
            logger.warning("Client manager already running")
            return
        
        self.is_running = True
        
        # Start heartbeat monitor
        self.heartbeat_monitor_thread = threading.Thread(
            target=self._monitor_heartbeats,
            daemon=True,
            name="FedClientHeartbeatMonitor"
        )
        self.heartbeat_monitor_thread.start()
        
        # Start model distributor
        self.model_distributor_thread = threading.Thread(
            target=self._model_distributor_worker,
            daemon=True,
            name="FedModelDistributor"
        )
        self.model_distributor_thread.start()
        
        logger.info("FederatedClientManager started")
    
    def stop(self):
        """Stop background monitoring threads."""
        self.is_running = False
        
        if self.heartbeat_monitor_thread:
            self.heartbeat_monitor_thread.join(timeout=5)
        
        if self.model_distributor_thread:
            self.model_distributor_thread.join(timeout=5)
        
        logger.info("FederatedClientManager stopped")
    
    def register_client(
        self,
        organization: str,
        subnet: str,
        server_url: str,
        metadata: Optional[Dict] = None
    ) -> Dict[str, str]:
        """
        Register a new federated client.
        
        Args:
            organization: Organization name
            subnet: Subnet/CIDR for this client
            server_url: Client's server URL for model download
            metadata: Additional client metadata
            
        Returns:
            Dictionary with client_id and api_key
        """
        try:
            # Generate client ID
            client_id = f"fed-{secrets.token_hex(8)}"
            api_key = secrets.token_hex(32)
            
            client_info = ClientInfo(
                client_id=client_id,
                organization=organization,
                subnet=subnet,
                server_url=server_url,
                api_key=api_key,
                registered_at=datetime.utcnow(),
                client_metadata=metadata or {}
            )
            
            with self.client_lock:
                self.clients[client_id] = client_info
            
            # Initialize heartbeat tracking
            self.heartbeat_history[client_id] = []
            
            logger.info(f"Registered client {client_id} for organization {organization}")
            
            return {
                'client_id': client_id,
                'api_key': api_key,
                'server_url': self.server_url,
                'status': 'registered',
                'message': f'Client {client_id} registered successfully'
            }
        
        except Exception as e:
            logger.exception("Error registering client")
            raise
    
    def deregister_client(self, client_id: str) -> bool:
        """Deregister a client."""
        try:
            with self.client_lock:
                if client_id in self.clients:
                    del self.clients[client_id]
                    logger.info(f"Deregistered client {client_id}")
                    return True
            return False
        except Exception as e:
            logger.exception(f"Error deregistering client {client_id}")
            raise
    
    def heartbeat(
        self,
        client_id: str,
        flows_processed: int,
        attacks_detected: int,
        model_version: Optional[str] = None,
        local_accuracy: Optional[float] = None
    ) -> bool:
        """
        Record client heartbeat.
        
        Args:
            client_id: Client identifier
            flows_processed: Number of flows processed since last heartbeat
            attacks_detected: Number of attacks detected
            model_version: Current model version
            local_accuracy: Local model accuracy
            
        Returns:
            True if heartbeat recorded successfully
        """
        try:
            with self.client_lock:
                if client_id not in self.clients:
                    logger.warning(f"Heartbeat from unregistered client {client_id}")
                    return False
                
                # Update client status
                client_info = self.clients[client_id]
                client_info.last_heartbeat = datetime.utcnow()
                client_info.total_flows_seen += flows_processed
                client_info.total_attacks_detected += attacks_detected
                
                if model_version:
                    client_info.current_model_version = model_version
                if local_accuracy is not None:
                    client_info.local_accuracy = local_accuracy
            
            # Record heartbeat
            heartbeat = ClientHeartbeat(
                client_id=client_id,
                flows_processed=flows_processed,
                attacks_detected=attacks_detected,
                model_version=model_version,
                local_accuracy=local_accuracy,
                status=ClientStatus.ONLINE
            )
            
            self.heartbeats[client_id] = heartbeat
            self.heartbeat_history[client_id].append(heartbeat)
            
            # Keep only last 1000 heartbeats per client
            if len(self.heartbeat_history[client_id]) > 1000:
                self.heartbeat_history[client_id] = self.heartbeat_history[client_id][-1000:]
            
            logger.debug(f"Heartbeat recorded for client {client_id}")
            return True
        
        except Exception as e:
            logger.exception(f"Error recording heartbeat for client {client_id}")
            return False
    
    def get_client_list(self) -> List[Dict]:
        """Get list of all registered clients."""
        try:
            with self.client_lock:
                result = []
                for client_id, client_info in self.clients.items():
                    heartbeat = self.heartbeats.get(client_id)
                    status = ClientStatus.OFFLINE
                    
                    if heartbeat:
                        time_since_heartbeat = (datetime.utcnow() - heartbeat.timestamp).total_seconds()
                        if time_since_heartbeat < self.heartbeat_timeout_seconds:
                            status = ClientStatus.ONLINE
                        else:
                            status = ClientStatus.OFFLINE
                    
                    result.append({
                        'client_id': client_id,
                        'organization': client_info.organization,
                        'subnet': client_info.subnet,
                        'status': status.value,
                        'registered_at': client_info.registered_at.isoformat(),
                        'last_heartbeat': heartbeat.timestamp.isoformat() if heartbeat else None,
                        'total_flows_seen': client_info.total_flows_seen,
                        'total_attacks_detected': client_info.total_attacks_detected,
                        'total_training_rounds': client_info.total_training_rounds,
                        'local_accuracy': client_info.local_accuracy,
                        'current_model_version': client_info.current_model_version
                    })
                
                return result
        
        except Exception as e:
            logger.exception("Error getting client list")
            return []
    
    def get_online_clients(self) -> List[str]:
        """Get list of currently online clients."""
        online_clients = []
        
        with self.client_lock:
            for client_id, client_info in self.clients.items():
                heartbeat = self.heartbeats.get(client_id)
                
                if heartbeat:
                    time_since_heartbeat = (datetime.utcnow() - heartbeat.timestamp).total_seconds()
                    if time_since_heartbeat < self.heartbeat_timeout_seconds:
                        online_clients.append(client_id)
        
        return online_clients
    
    def distribute_model_update(
        self,
        model_version: str,
        model_hash: str,
        download_url: str,
        target_clients: Optional[List[str]] = None
    ) -> Dict:
        """
        Queue model update for distribution to clients.
        
        Args:
            model_version: Version string for the model
            model_hash: Hash of the model for verification
            download_url: URL where clients can download the model
            target_clients: Specific clients to target (None = all online)
            
        Returns:
            Distribution task details
        """
        try:
            if target_clients is None:
                target_clients = self.get_online_clients()
            
            task = {
                'task_id': secrets.token_hex(8),
                'model_version': model_version,
                'model_hash': model_hash,
                'download_url': download_url,
                'target_clients': target_clients,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'queued'
            }
            
            self.model_update_queue.put(task)
            
            logger.info(
                f"Model update v{model_version} queued for {len(target_clients)} clients: "
                f"{task['task_id']}"
            )
            
            return task
        
        except Exception as e:
            logger.exception("Error queueing model update")
            raise
    
    def _monitor_heartbeats(self):
        """Background thread: Monitor client heartbeats and detect offline clients."""
        while self.is_running:
            try:
                with self.client_lock:
                    offline_clients = []
                    
                    for client_id, heartbeat in list(self.heartbeats.items()):
                        time_since_heartbeat = (datetime.utcnow() - heartbeat.timestamp).total_seconds()
                        
                        if time_since_heartbeat > self.heartbeat_timeout_seconds:
                            offline_clients.append(client_id)
                            logger.warning(
                                f"Client {client_id} offline for {time_since_heartbeat:.0f}s"
                            )
                    
                    # Mark offline clients
                    for client_id in offline_clients:
                        if client_id in self.clients:
                            # Keep client registered but mark as offline
                            pass
                
                threading.Event().wait(30)  # Check every 30 seconds
            
            except Exception as e:
                logger.exception("Error in heartbeat monitor")
                threading.Event().wait(30)
    
    def _model_distributor_worker(self):
        """Background thread: Distribute model updates to clients."""
        while self.is_running:
            try:
                # Check for pending model updates
                if not self.model_update_queue.empty():
                    try:
                        task = self.model_update_queue.get_nowait()
                        self._distribute_model_to_clients(task)
                    except queue.Empty:
                        pass
                
                threading.Event().wait(5)  # Check every 5 seconds
            
            except Exception as e:
                logger.exception("Error in model distributor")
                threading.Event().wait(5)
    
    def _distribute_model_to_clients(self, task: Dict):
        """Distribute a model update to target clients."""
        try:
            model_version = task['model_version']
            target_clients = task['target_clients']
            
            with self.client_lock:
                for client_id in target_clients:
                    if client_id in self.clients:
                        client_info = self.clients[client_id]
                        
                        logger.info(
                            f"Distributing model v{model_version} to {client_id} "
                            f"({client_info.organization})"
                        )
                        
                        # In production, would use actual API to push model
                        # For now, just record the update
            
            task['status'] = 'distributed'
            task['distributed_at'] = datetime.utcnow().isoformat()
            
            logger.info(f"Model distribution task {task['task_id']} completed")
        
        except Exception as e:
            logger.exception(f"Error distributing model")
            task['status'] = 'failed'
            task['error'] = str(e)


@dataclass
class ClientInfo:
    """Information about a registered federated client."""
    client_id: str
    organization: str
    subnet: str
    server_url: str
    api_key: str
    
    # Tracking
    registered_at: datetime = field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = field(default_factory=datetime.utcnow)
    last_training_round: Optional[datetime] = None
    
    # Statistics
    total_flows_seen: int = 0
    total_attacks_detected: int = 0
    total_training_rounds: int = 0
    
    # Performance
    local_accuracy: Optional[float] = None
    current_model_version: str = "v1"
    
    # Metadata
    client_metadata: Dict = field(default_factory=dict)
    
    def is_online(self, timeout_seconds: int = 300) -> bool:
        """Check if client is currently online."""
        time_since_heartbeat = (datetime.utcnow() - self.last_heartbeat).total_seconds()
        return time_since_heartbeat < timeout_seconds
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'client_id': self.client_id,
            'organization': self.organization,
            'subnet': self.subnet,
            'status': 'online' if self.is_online() else 'offline',
            'registered_at': self.registered_at.isoformat(),
            'last_heartbeat': self.last_heartbeat.isoformat(),
            'total_flows_seen': self.total_flows_seen,
            'total_attacks_detected': self.total_attacks_detected,
            'total_training_rounds': self.total_training_rounds,
            'local_accuracy': self.local_accuracy,
            'current_model_version': self.current_model_version
        }


# Global instance
_global_client_manager: Optional[FederatedClientManager] = None


def get_client_manager() -> FederatedClientManager:
    """Get or create global client manager instance."""
    global _global_client_manager
    
    if _global_client_manager is None:
        _global_client_manager = FederatedClientManager()
        _global_client_manager.start()
    
    return _global_client_manager
