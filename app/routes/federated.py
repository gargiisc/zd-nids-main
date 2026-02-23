#!/usr/bin/env python3
"""
Integration: Add Federated Learning to Flask Dashboard
======================================================
This file adds federated learning routes to the Flask app.

Installation:
    1. Copy this file to: app/routes/federated.py
    2. In app/__init__.py, add:
       from app.routes.federated import federated_bp
       app.register_blueprint(federated_bp)
"""

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

federated_bp = Blueprint('federated', __name__, url_prefix='/api/federated')

# Global server instance (will be set when server starts)
_fed_server = None


def set_federation_server(server):
    """Set the global federation server instance."""
    global _fed_server
    _fed_server = server


# ==================== Client Registration (New Real-Time) ====================

@federated_bp.route('/register', methods=['POST'])
def register_client_real_time():
    """
    Register a new federated client.
    Real-time endpoint for client registration.
    
    Request JSON:
    {
        "organization": "Hospital A",
        "subnet": "192.168.1.0/24",
        "server_url": "http://hospital-a.local:8001",
        "metadata": {"version": "1.0", "device": "network_tap"}
    }
    
    Response:
    {
        "client_id": "fed-abc123",
        "api_key": "key_xyz789",
        "server_url": "http://central-server:8080",
        "status": "registered"
    }
    """
    try:
        from federated.federated_client_manager import get_client_manager
        from app.models.database import db, FederatedClient
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        organization = data.get('organization')
        subnet = data.get('subnet')
        server_url = data.get('server_url')
        metadata = data.get('metadata', {})
        
        if not all([organization, subnet, server_url]):
            return jsonify({
                'error': 'Missing required fields: organization, subnet, server_url'
            }), 400
        
        # Get client manager
        manager = get_client_manager()
        
        # Register client
        result = manager.register_client(
            organization=organization,
            subnet=subnet,
            server_url=server_url,
            metadata=metadata
        )
        
        # Store in database
        fed_client = FederatedClient(
            client_id=result['client_id'],
            organization=organization,
            subnet=subnet,
            server_url=server_url,
            api_key=result['api_key'],
            is_active=True,
            metadata=str(metadata)
        )
        db.session.add(fed_client)
        db.session.commit()
        
        logger.info(f"Client registered: {result['client_id']} for {organization}")
        
        return jsonify(result), 201
    
    except Exception as e:
        logger.exception("Error registering client")
        return jsonify({'error': str(e)}), 500


@federated_bp.route('/heartbeat', methods=['POST'])
def client_heartbeat():
    """
    Client heartbeat endpoint.
    Clients send periodic heartbeats with their status.
    
    Request JSON:
    {
        "client_id": "fed-abc123",
        "flows_processed": 1000,
        "attacks_detected": 5,
        "model_version": "v2.1",
        "local_accuracy": 0.96
    }
    """
    try:
        from federated.federated_client_manager import get_client_manager
        from app.models.database import db, FederatedClient
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        client_id = data.get('client_id')
        if not client_id:
            return jsonify({'error': 'client_id required'}), 400
        
        flows_processed = data.get('flows_processed', 0)
        attacks_detected = data.get('attacks_detected', 0)
        model_version = data.get('model_version')
        local_accuracy = data.get('local_accuracy')
        
        # Get client manager
        manager = get_client_manager()
        
        # Record heartbeat
        success = manager.heartbeat(
            client_id=client_id,
            flows_processed=flows_processed,
            attacks_detected=attacks_detected,
            model_version=model_version,
            local_accuracy=local_accuracy
        )
        
        if not success:
            return jsonify({'error': 'Client not found or heartbeat failed'}), 404
        
        # Update database
        fed_client = db.session.query(FederatedClient).filter(
            FederatedClient.client_id == client_id
        ).first()
        
        if fed_client:
            fed_client.last_heartbeat = datetime.utcnow()
            fed_client.total_flows_seen += flows_processed
            fed_client.total_attacks_detected += attacks_detected
            if model_version:
                fed_client.metadata = f'{{"version": "{model_version}"}}'
            if local_accuracy is not None:
                fed_client.local_accuracy = local_accuracy
            db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Heartbeat recorded',
            'server_timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.exception("Error processing heartbeat")
        return jsonify({'error': str(e)}), 500


@federated_bp.route('/clients/real-time', methods=['GET'])
@login_required
def get_clients_real_time():
    """
    Get all federated clients with real-time status.
    """
    try:
        from federated.federated_client_manager import get_client_manager
        from app.models.database import db, FederatedClient
        
        manager = get_client_manager()
        clients_list = manager.get_client_list()
        
        # Enrich with database info
        for client in clients_list:
            db_client = db.session.query(FederatedClient).filter(
                FederatedClient.client_id == client['client_id']
            ).first()
            
            if db_client:
                client['total_flows_seen'] = db_client.total_flows_seen
                client['total_attacks_detected'] = db_client.total_attacks_detected
        
        return jsonify({
            'total_clients': len(clients_list),
            'online_clients': len([c for c in clients_list if c['status'] == 'online']),
            'clients': clients_list
        })
    
    except Exception as e:
        logger.exception("Error fetching clients")
        return jsonify({'error': str(e)}), 500


@federated_bp.route('/clients/<client_id>/status', methods=['GET'])
@login_required
def get_client_status_real_time(client_id):
    """
    Get detailed status of a specific client.
    """
    try:
        from federated.federated_client_manager import get_client_manager
        from app.models.database import db, FederatedClient
        
        manager = get_client_manager()
        clients = manager.get_client_list()
        
        client = next((c for c in clients if c['client_id'] == client_id), None)
        if not client:
            return jsonify({'error': 'Client not found'}), 404
        
        # Get database details
        db_client = db.session.query(FederatedClient).filter(
            FederatedClient.client_id == client_id
        ).first()
        
        if db_client:
            client['epsilon_spent'] = db_client.epsilon_spent
            client['local_precision'] = db_client.local_precision
            client['local_recall'] = db_client.local_recall
        
        return jsonify(client)
    
    except Exception as e:
        logger.exception("Error fetching client status")
        return jsonify({'error': str(e)}), 500


# ==================== Model Distribution (New Real-Time) ====================

@federated_bp.route('/distribute-model', methods=['POST'])
@login_required
def distribute_model_real_time():
    """
    Queue a model update for distribution to clients.
    
    Request JSON:
    {
        "model_version": "v2.2",
        "model_hash": "abc123def456",
        "download_url": "http://central-server:8080/models/v2.2",
        "target_clients": ["fed-abc123", "fed-xyz789"] (optional, all online if not provided)
    }
    """
    try:
        from federated.federated_client_manager import get_client_manager
        from app.models.database import db, FederatedRound
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        model_version = data.get('model_version')
        model_hash = data.get('model_hash')
        download_url = data.get('download_url')
        target_clients = data.get('target_clients')
        
        if not all([model_version, model_hash, download_url]):
            return jsonify({
                'error': 'Missing required fields: model_version, model_hash, download_url'
            }), 400
        
        manager = get_client_manager()
        
        # Queue model update
        task = manager.distribute_model_update(
            model_version=model_version,
            model_hash=model_hash,
            download_url=download_url,
            target_clients=target_clients
        )
        
        return jsonify({
            'success': True,
            'task_id': task['task_id'],
            'model_version': model_version,
            'target_clients_count': len(task['target_clients']),
            'status': task['status']
        }), 202
    
    except Exception as e:
        logger.exception("Error distributing model")
        return jsonify({'error': str(e)}), 500


# ==================== Status Endpoints ====================

@federated_bp.route('/status', methods=['GET'])
@login_required
def federation_status():
    """Get current federation status."""
    if _fed_server is None:
        return jsonify({
            'error': 'Federation server not initialized',
            'initialized': False
        }), 503
    
    return jsonify({
        'initialized': True,
        'server_id': _fed_server.config.server_id,
        'current_round': _fed_server.current_round,
        'registered_clients': _fed_server.get_client_count(),
        'model_version': _fed_server.global_model_version,
        'rounds_completed': len(_fed_server.round_history),
        'last_round_time': _fed_server.last_round_time.isoformat() if _fed_server.last_round_time else None
    })


@federated_bp.route('/health', methods=['GET'])
def federation_health():
    """Health check for federation server."""
    return jsonify({
        'status': 'ok' if _fed_server else 'not_initialized',
        'timestamp': __import__('datetime').datetime.utcnow().isoformat()
    })


# ==================== Client Management ====================

@federated_bp.route('/clients', methods=['GET'])
@login_required
def list_clients():
    """List all registered clients with their stats."""
    if _fed_server is None:
        return jsonify([])
    
    clients = []
    for client_id, client_info in _fed_server.registered_clients.items():
        clients.append({
            'id': client_id,
            'organization': client_info.organization,
            'subnet': client_info.subnet,
            'samples_contributed': client_info.total_samples_contributed,
            'rounds_participated': client_info.rounds_participated,
            'reliability_score': round(client_info.reliability_score, 3),
            'avg_accuracy': round(client_info.avg_accuracy, 4),
            'avg_loss': round(client_info.avg_loss, 4),
            'last_seen': client_info.last_seen.isoformat(),
            'registered_at': client_info.registered_at.isoformat()
        })
    
    return jsonify(clients)


@federated_bp.route('/clients/<client_id>', methods=['GET'])
@login_required
def get_client(client_id):
    """Get details for a specific client."""
    if _fed_server is None:
        return jsonify({'error': 'Server not initialized'}), 503
    
    client_info = _fed_server.registered_clients.get(client_id)
    if not client_info:
        return jsonify({'error': 'Client not found'}), 404
    
    return jsonify({
        'id': client_id,
        'organization': client_info.organization,
        'subnet': client_info.subnet,
        'samples_contributed': client_info.total_samples_contributed,
        'rounds_participated': client_info.rounds_participated,
        'reliability_score': client_info.reliability_score,
        'avg_accuracy': client_info.avg_accuracy,
        'avg_loss': client_info.avg_loss,
        'avg_training_time': client_info.avg_training_time,
        'last_seen': client_info.last_seen.isoformat(),
        'last_contribution': client_info.last_contribution.isoformat() if client_info.last_contribution else None,
        'registered_at': client_info.registered_at.isoformat()
    })


@federated_bp.route('/clients/<client_id>/remove', methods=['POST'])
@login_required
def remove_client(client_id):
    """Remove a client from federation (admin only)."""
    if _fed_server is None:
        return jsonify({'error': 'Server not initialized'}), 503
    
    if _fed_server.remove_client(client_id):
        return jsonify({'success': True, 'message': f'Client {client_id} removed'})
    else:
        return jsonify({'error': 'Client not found'}), 404


# ==================== Round Management ====================

@federated_bp.route('/rounds', methods=['GET'])
@login_required
def get_round_history():
    """Get federation round history."""
    if _fed_server is None:
        return jsonify([])
    
    limit = request.args.get('limit', 50, type=int)
    rounds = []
    
    for round_info in _fed_server.round_history[-limit:]:
        rounds.append({
            'round': round_info.round_number,
            'started': round_info.started_at.isoformat(),
            'completed': round_info.completed_at.isoformat() if round_info.completed_at else None,
            'selected_clients': len(round_info.selected_clients),
            'participating_clients': len(round_info.participating_clients),
            'total_samples': round_info.total_samples,
            'avg_loss': round(round_info.avg_loss, 4),
            'avg_accuracy': round(round_info.avg_accuracy, 4),
            'model_version': round_info.model_version
        })
    
    return jsonify(rounds)


@federated_bp.route('/rounds/<int:round_num>', methods=['GET'])
@login_required
def get_round(round_num):
    """Get details for a specific round."""
    if _fed_server is None:
        return jsonify({'error': 'Server not initialized'}), 503
    
    # Find round in history
    round_info = None
    for r in _fed_server.round_history:
        if r.round_number == round_num:
            round_info = r
            break
    
    if not round_info:
        return jsonify({'error': 'Round not found'}), 404
    
    return jsonify(round_info.to_dict())


# ==================== Control Endpoints ====================

@federated_bp.route('/start', methods=['POST'])
@login_required
def start_federation():
    """Start federated learning rounds."""
    if _fed_server is None:
        return jsonify({'error': 'Server not initialized'}), 503
    
    num_rounds = request.json.get('rounds', 100) if request.json else 100
    
    try:
        # Start in background thread
        import threading
        thread = threading.Thread(
            target=_fed_server.start_round_scheduler,
            args=(num_rounds,),
            daemon=True
        )
        thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Federation started for {num_rounds} rounds'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@federated_bp.route('/stop', methods=['POST'])
@login_required
def stop_federation():
    """Stop federated learning."""
    if _fed_server is None:
        return jsonify({'error': 'Server not initialized'}), 503
    
    try:
        _fed_server.stop()
        return jsonify({'success': True, 'message': 'Federation stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


# ==================== Statistics Endpoints ====================

@federated_bp.route('/stats', methods=['GET'])
@login_required
def federation_stats():
    """Get comprehensive federation statistics."""
    if _fed_server is None:
        return jsonify({})
    
    total_samples = sum(
        c.total_samples_contributed
        for c in _fed_server.registered_clients.values()
    )
    
    avg_reliability = (
        sum(c.reliability_score for c in _fed_server.registered_clients.values()) /
        max(1, len(_fed_server.registered_clients))
    )
    
    return jsonify({
        'total_clients': _fed_server.get_client_count(),
        'total_samples': total_samples,
        'rounds_completed': len(_fed_server.round_history),
        'current_round': _fed_server.current_round,
        'model_version': _fed_server.global_model_version,
        'avg_client_reliability': round(avg_reliability, 3),
        'aggregation_strategy': _fed_server.config.aggregation_strategy.value
    })


@federated_bp.route('/metrics', methods=['GET'])
@login_required
def federation_metrics():
    """Get detailed metrics for federation."""
    if _fed_server is None:
        return jsonify({})
    
    # Aggregate metrics from round history
    if not _fed_server.round_history:
        return jsonify({
            'rounds': [],
            'avg_accuracy': 0,
            'avg_loss': 0,
            'total_samples': 0
        })
    
    rounds = []
    accuracies = []
    losses = []
    
    for round_info in _fed_server.round_history[-100:]:  # Last 100 rounds
        rounds.append({
            'round': round_info.round_number,
            'accuracy': round_info.avg_accuracy,
            'loss': round_info.avg_loss,
            'samples': round_info.total_samples,
            'clients': len(round_info.participating_clients)
        })
        accuracies.append(round_info.avg_accuracy)
        losses.append(round_info.avg_loss)
    
    return jsonify({
        'rounds': rounds,
        'avg_accuracy': sum(accuracies) / len(accuracies) if accuracies else 0,
        'avg_loss': sum(losses) / len(losses) if losses else 0,
        'total_samples': sum(r['samples'] for r in rounds),
        'best_accuracy': max(accuracies) if accuracies else 0,
        'best_loss': min(losses) if losses else float('inf')
    })


# ==================== Dashboard Template Route ====================

@federated_bp.route('/dashboard')
@login_required
def federation_dashboard():
    """Render federated learning dashboard."""
    return render_template('federated_dashboard.html')
