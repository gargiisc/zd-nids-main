"""
Federated Clients API and Real-Time Updates
============================================
Provides endpoints for fetching federated client metadata and real-time updates
via Server-Sent Events (SSE).

Features:
- Get all connected clients with metadata
- Real-time SSE stream for client updates
- Client status tracking (online/offline/training)
- Training round metrics aggregation
- Privacy-preserving data exposure (metadata only)
"""

from flask import Blueprint, jsonify, request, Response, current_app
from flask_login import login_required
from datetime import datetime, timedelta
from functools import wraps
import logging
import json
import queue
import threading
from collections import defaultdict

from app import db
from app.models.database import FederatedClient

logger = logging.getLogger(__name__)

federated_clients_bp = Blueprint(
    'federated_clients',
    __name__,
    url_prefix='/api/federated-clients'
)

# Global event queues for SSE streams (client_id -> queue)
_sse_queues = {}
_sse_queues_lock = threading.Lock()


class ClientStatusTracker:
    """Tracks real-time client status and metrics."""
    
    def __init__(self):
        self.client_status = {}
        self.training_rounds = defaultdict(list)
        self.lock = threading.Lock()
    
    def update_status(self, client_id, status_data):
        """Update client status and broadcast to SSE subscribers."""
        with self.lock:
            self.client_status[client_id] = {
                'timestamp': datetime.utcnow().isoformat(),
                'status': status_data.get('status', 'offline'),
                'training_round': status_data.get('training_round', 0),
                'flows_processed': status_data.get('flows_processed', 0),
                'attacks_detected': status_data.get('attacks_detected', 0),
                'model_loss': status_data.get('model_loss'),
                'model_accuracy': status_data.get('model_accuracy'),
                'last_update': datetime.utcnow().isoformat()
            }
            
            # Store training round data
            if status_data.get('status') == 'training':
                self.training_rounds[client_id].append({
                    'round': status_data.get('training_round', 0),
                    'loss': status_data.get('model_loss'),
                    'accuracy': status_data.get('model_accuracy'),
                    'timestamp': datetime.utcnow().isoformat()
                })
                # Keep only last 100 rounds per client
                if len(self.training_rounds[client_id]) > 100:
                    self.training_rounds[client_id] = self.training_rounds[client_id][-100:]
        
        # Broadcast to SSE subscribers
        self._broadcast_update('client_update', {
            'client_id': client_id,
            'data': self.client_status[client_id]
        })
    
    def get_client_status(self, client_id):
        """Get current status of a specific client."""
        with self.lock:
            return self.client_status.get(client_id, {})
    
    def get_all_statuses(self):
        """Get status of all clients."""
        with self.lock:
            return dict(self.client_status)
    
    def get_training_history(self, client_id, limit=50):
        """Get training history for a client."""
        with self.lock:
            history = self.training_rounds.get(client_id, [])
            return history[-limit:] if history else []
    
    def _broadcast_update(self, event_type, data):
        """Broadcast update to all SSE subscribers."""
        with _sse_queues_lock:
            for queue_obj in _sse_queues.values():
                try:
                    queue_obj.put_nowait({
                        'event': event_type,
                        'data': data,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                except queue.Full:
                    # Queue is full, skip this subscriber
                    pass


# Global tracker instance
_client_tracker = ClientStatusTracker()


def get_client_tracker():
    """Get the global client status tracker."""
    return _client_tracker


# ==================== API Endpoints ====================

@federated_clients_bp.route('/list', methods=['GET'])
@login_required
def list_federated_clients():
    """
    Get list of all federated clients with metadata.
    
    Query Parameters:
    - status: Filter by status (online/offline/training)
    - limit: Maximum number of clients to return (default: 100)
    - sort_by: Sort field (organization, last_heartbeat, etc.)
    
    Returns:
    {
        "total": 5,
        "clients": [
            {
                "id": "fed-abc123",
                "organization": "Hospital A",
                "subnet": "192.168.1.0/24",
                "status": "online",
                "connection_status": "online",
                "training_round": 42,
                "last_update": "2026-01-28T10:30:45Z",
                "local_accuracy": 0.96,
                "local_loss": 0.05,
                "flows_processed": 15000,
                "attacks_detected": 12,
                "registered_at": "2026-01-15T08:00:00Z",
                "is_online": true,
                "online_since": "2h 30m ago"
            },
            ...
        ]
    }
    """
    try:
        status_filter = request.args.get('status', '').lower()
        limit = int(request.args.get('limit', 100))
        sort_by = request.args.get('sort_by', 'organization')
        
        # Query clients
        query = FederatedClient.query.filter_by(is_active=True)
        
        if status_filter in ['online', 'offline', 'training']:
            # Filter by status if specified
            if status_filter == 'online':
                cutoff_time = datetime.utcnow() - timedelta(seconds=300)
                query = query.filter(FederatedClient.last_heartbeat >= cutoff_time)
            elif status_filter == 'offline':
                cutoff_time = datetime.utcnow() - timedelta(seconds=300)
                query = query.filter(
                    (FederatedClient.last_heartbeat < cutoff_time) |
                    (FederatedClient.last_heartbeat == None)
                )
        
        # Sort
        if sort_by == 'organization':
            query = query.order_by(FederatedClient.organization.asc())
        elif sort_by == 'last_heartbeat':
            query = query.order_by(FederatedClient.last_heartbeat.desc())
        
        clients = query.limit(limit).all()
        
        # Enrich with real-time status
        tracker = get_client_tracker()
        client_list = []
        
        for client in clients:
            is_online = client.is_online()
            last_hb = client.last_heartbeat
            
            # Calculate online duration
            online_since = "Never"
            if last_hb:
                delta = datetime.utcnow() - last_hb
                if is_online:
                    hours = delta.total_seconds() // 3600
                    minutes = (delta.total_seconds() % 3600) // 60
                    if hours > 0:
                        online_since = f"{int(hours)}h {int(minutes)}m ago"
                    else:
                        online_since = f"{int(minutes)}m ago"
                else:
                    online_since = last_hb.strftime('%Y-%m-%d %H:%M:%S UTC')
            
            # Get real-time status data
            rt_status = tracker.get_client_status(client.client_id)
            
            client_list.append({
                'id': client.client_id,
                'organization': client.organization,
                'subnet': client.subnet,
                'status': rt_status.get('status', 'offline'),
                'connection_status': 'online' if is_online else 'offline',
                'training_round': rt_status.get('training_round', client.total_training_rounds or 0),
                'last_update': rt_status.get('last_update', 
                                            last_hb.isoformat() if last_hb else None),
                'local_accuracy': rt_status.get('model_accuracy') or client.local_accuracy or 0.0,
                'local_loss': rt_status.get('model_loss') or 0.0,
                'flows_processed': rt_status.get('flows_processed', client.total_flows_seen or 0),
                'attacks_detected': rt_status.get('attacks_detected', client.total_attacks_detected or 0),
                'registered_at': client.registered_at.isoformat() if client.registered_at else None,
                'is_online': is_online,
                'online_since': online_since,
                'epsilon_spent': float(client.epsilon_spent or 0.0)
            })
        
        return jsonify({
            'total': len(client_list),
            'clients': client_list
        }), 200
    
    except Exception as e:
        logger.exception("Error fetching federated clients")
        return jsonify({'error': str(e)}), 500


@federated_clients_bp.route('/client/<client_id>', methods=['GET'])
@login_required
def get_client_details(client_id):
    """
    Get detailed information about a specific federated client.
    
    Includes training history, performance trends, and metadata.
    """
    try:
        client = FederatedClient.query.filter_by(client_id=client_id).first()
        if not client:
            return jsonify({'error': 'Client not found'}), 404
        
        tracker = get_client_tracker()
        rt_status = tracker.get_client_status(client_id)
        training_history = tracker.get_training_history(client_id, limit=100)
        
        # Parse metadata
        try:
            metadata = json.loads(client.client_metadata) if client.client_metadata else {}
        except:
            metadata = {}
        
        return jsonify({
            'client': {
                'id': client.client_id,
                'organization': client.organization,
                'subnet': client.subnet,
                'registered_at': client.registered_at.isoformat() if client.registered_at else None,
                'server_url': client.server_url,
                'is_active': client.is_active,
                'metadata': metadata
            },
            'current_status': rt_status,
            'statistics': {
                'total_flows_seen': client.total_flows_seen or 0,
                'total_attacks_detected': client.total_attacks_detected or 0,
                'total_training_rounds': client.total_training_rounds or 0,
                'local_accuracy': client.local_accuracy or 0.0,
                'local_precision': client.local_precision or 0.0,
                'local_recall': client.local_recall or 0.0,
                'epsilon_spent': float(client.epsilon_spent or 0.0)
            },
            'training_history': training_history
        }), 200
    
    except Exception as e:
        logger.exception(f"Error fetching client details for {client_id}")
        return jsonify({'error': str(e)}), 500


@federated_clients_bp.route('/stats', methods=['GET'])
@login_required
def get_federated_stats():
    """
    Get aggregated statistics across all federated clients.
    
    Returns:
    {
        "total_clients": 5,
        "online_clients": 4,
        "offline_clients": 1,
        "avg_accuracy": 0.94,
        "avg_loss": 0.08,
        "total_flows_aggregated": 75000,
        "total_attacks_detected": 120,
        "active_training_rounds": 3,
        "avg_epsilon_spent": 0.25
    }
    """
    try:
        all_clients = FederatedClient.query.filter_by(is_active=True).all()
        tracker = get_client_tracker()
        
        total = len(all_clients)
        online_count = sum(1 for c in all_clients if c.is_online())
        offline_count = total - online_count
        
        # Aggregate metrics
        accuracies = []
        losses = []
        training_round_count = 0
        total_flows = 0
        total_attacks = 0
        total_epsilon = 0.0
        
        for client in all_clients:
            rt_status = tracker.get_client_status(client.client_id)
            
            if rt_status.get('model_accuracy'):
                accuracies.append(rt_status['model_accuracy'])
            elif client.local_accuracy:
                accuracies.append(client.local_accuracy)
            
            if rt_status.get('model_loss'):
                losses.append(rt_status['model_loss'])
            
            if rt_status.get('status') == 'training':
                training_round_count += 1
            
            total_flows += rt_status.get('flows_processed', client.total_flows_seen or 0)
            total_attacks += rt_status.get('attacks_detected', client.total_attacks_detected or 0)
            total_epsilon += client.epsilon_spent or 0.0
        
        avg_accuracy = sum(accuracies) / len(accuracies) if accuracies else 0.0
        avg_loss = sum(losses) / len(losses) if losses else 0.0
        
        return jsonify({
            'total_clients': total,
            'online_clients': online_count,
            'offline_clients': offline_count,
            'avg_accuracy': round(avg_accuracy, 4),
            'avg_loss': round(avg_loss, 4),
            'total_flows_aggregated': total_flows,
            'total_attacks_detected': total_attacks,
            'active_training_rounds': training_round_count,
            'avg_epsilon_spent': round(total_epsilon / total if total > 0 else 0.0, 4)
        }), 200
    
    except Exception as e:
        logger.exception("Error fetching federated stats")
        return jsonify({'error': str(e)}), 500


@federated_clients_bp.route('/update-status', methods=['POST'])
def update_client_status():
    """
    Internal endpoint for clients to report their status.
    Called by federated clients to update their metrics.
    
    Request JSON:
    {
        "client_id": "fed-abc123",
        "status": "online|training|offline",
        "training_round": 42,
        "model_accuracy": 0.96,
        "model_loss": 0.05,
        "flows_processed": 1000,
        "attacks_detected": 5
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        client_id = data.get('client_id')
        if not client_id:
            return jsonify({'error': 'client_id required'}), 400
        
        # Verify client exists
        client = FederatedClient.query.filter_by(client_id=client_id).first()
        if not client:
            return jsonify({'error': 'Client not found'}), 404
        
        # Update database
        client.last_heartbeat = datetime.utcnow()
        if data.get('status') == 'training':
            client.last_training_round = datetime.utcnow()
        
        if 'training_round' in data:
            client.total_training_rounds = data.get('training_round', 0)
        
        if 'model_accuracy' in data:
            client.local_accuracy = data.get('model_accuracy')
        
        if 'flows_processed' in data:
            client.total_flows_seen = data.get('flows_processed', 0)
        
        if 'attacks_detected' in data:
            client.total_attacks_detected = data.get('attacks_detected', 0)
        
        db.session.commit()
        
        # Update real-time tracker
        tracker = get_client_tracker()
        tracker.update_status(client_id, data)
        
        logger.info(f"Updated status for client {client_id}: {data.get('status')}")
        
        return jsonify({
            'status': 'updated',
            'client_id': client_id
        }), 200
    
    except Exception as e:
        logger.exception("Error updating client status")
        return jsonify({'error': str(e)}), 500


@federated_clients_bp.route('/stream', methods=['GET'])
@login_required
def stream_client_updates():
    """
    Server-Sent Events (SSE) stream for real-time client updates.
    
    Streams client status changes, training metrics, and connectivity events
    without requiring page refresh.
    
    Usage:
    ```javascript
    const eventSource = new EventSource('/api/federated-clients/stream');
    eventSource.addEventListener('client_update', function(event) {
        const data = JSON.parse(event.data);
        console.log('Client updated:', data);
    });
    ```
    """
    def generate():
        """Generate SSE events for client updates."""
        queue_obj = queue.Queue(maxsize=50)
        queue_id = id(queue_obj)
        
        # Register this queue
        with _sse_queues_lock:
            _sse_queues[queue_id] = queue_obj
        
        try:
            # Send initial data
            yield 'data: ' + json.dumps({
                'event': 'connection_established',
                'data': {
                    'message': 'Connected to federated clients stream',
                    'timestamp': datetime.utcnow().isoformat()
                }
            }) + '\n\n'
            
            # Stream updates
            while True:
                try:
                    # Wait for updates with timeout
                    event = queue_obj.get(timeout=30)
                    yield 'data: ' + json.dumps(event) + '\n\n'
                except queue.Empty:
                    # Send keep-alive comment
                    yield ': keep-alive\n\n'
        
        finally:
            # Cleanup
            with _sse_queues_lock:
                _sse_queues.pop(queue_id, None)
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


@federated_clients_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring."""
    try:
        online_count = FederatedClient.query.filter(
            FederatedClient.is_active == True,
            FederatedClient.last_heartbeat >= (datetime.utcnow() - timedelta(seconds=300))
        ).count()
        
        total_count = FederatedClient.query.filter_by(is_active=True).count()
        
        return jsonify({
            'status': 'healthy',
            'online_clients': online_count,
            'total_clients': total_count,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
