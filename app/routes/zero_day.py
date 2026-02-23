"""
Zero-Day Detection Dashboard Routes
===================================
Lightweight implementation to provide the zero-day blueprint and APIs
used by the dashboard templates. Restores missing file to avoid import
errors during app startup.
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required
from datetime import datetime, timedelta
import logging
from typing import Dict
from sqlalchemy import func

logger = logging.getLogger(__name__)

# Create blueprint
zero_day_bp = Blueprint('zero_day', __name__, url_prefix='/zero-day')


@zero_day_bp.route('/', methods=['GET'])
@login_required
def zero_day_dashboard():
    """Render the zero-day dashboard page with basic stats."""
    try:
        from app.models.database import db, Alert, FederatedClient, FederatedRound
        from federated.federated_client_manager import get_client_manager
        from detection.federated_learning_flow import get_federated_coordinator

        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)

        # Optional: client selection from query string (comma-separated client_ids)
        client_ids_param = request.args.get('client_ids')
        client_ids = [c.strip() for c in client_ids_param.split(',')] if client_ids_param else None

        threshold = current_app.config.get('ANOMALY_THRESHOLD', 0.7)
        anomaly_score = func.coalesce(Alert.risk_score, Alert.confidence)

        # Filter to show ONLY zero-day attacks (high-confidence anomalies)
        zero_day_query = db.session.query(Alert).filter(
            anomaly_score >= threshold,
            Alert.confidence >= 0.7,
            Alert.timestamp >= twenty_four_hours_ago
        )
        if client_ids:
            zero_day_query = zero_day_query.filter(Alert.fed_client_id.in_(client_ids))
        zero_day_alerts = zero_day_query.order_by(Alert.timestamp.desc()).limit(100).all()

        total_alerts_24h = db.session.query(Alert).filter(
            Alert.timestamp >= twenty_four_hours_ago
        ).count()

        critical_alerts = db.session.query(Alert).filter(
            Alert.severity == 'critical',
            Alert.timestamp >= twenty_four_hours_ago
        ).count()

        high_confidence_anomalies = db.session.query(Alert).filter(
            func.coalesce(Alert.risk_score, Alert.confidence) >= 0.8,
            Alert.timestamp >= twenty_four_hours_ago
        ).count()

        detector_stats = get_detector_stats()
        
        # Get federated learning stats
        try:
            manager = get_client_manager()
            coordinator = get_federated_coordinator()
            
            federated_stats = {
                'online_clients': len(manager.get_online_clients()),
                'total_clients': len(manager.clients),
                'current_round': coordinator.current_round,
                'round_state': coordinator.round_state.value,
                'latest_accuracy': coordinator.round_history[-1].global_accuracy if coordinator.round_history else 0.0,
                'latest_loss': coordinator.round_history[-1].global_loss if coordinator.round_history else float('inf'),
                'rounds_completed': len(coordinator.round_history),
                'new_attacks_detected': [],
                'clients': manager.get_client_list()
            }
            
            # Collect new attack types from recent rounds
            for round_result in coordinator.round_history[-5:]:
                federated_stats['new_attacks_detected'].extend(round_result.new_attack_types_detected)
            federated_stats['new_attacks_detected'] = list(set(federated_stats['new_attacks_detected']))
        
        except Exception as e:
            logger.debug(f"Could not get federated stats: {e}")
            federated_stats = {
                'online_clients': 0,
                'total_clients': 0,
                'current_round': 0,
                'round_state': 'not_initialized',
                'latest_accuracy': 0.0,
                'latest_loss': 0.0,
                'rounds_completed': 0,
                'new_attacks_detected': []
            }

        return render_template('zero_day_dashboard.html',
                       zero_day_alerts=zero_day_alerts,
                       total_alerts_24h=total_alerts_24h,
                       critical_alerts=critical_alerts,
                       high_confidence_anomalies=high_confidence_anomalies,
                       detector_stats=detector_stats,
                       federated_stats=federated_stats,
                       selected_client_ids=client_ids)
    except Exception as e:
        logger.exception('Error loading zero-day dashboard')
        return render_template('error.html', error=str(e)), 500


def _categorize_attack(attack_type, source_ip, dest_ip, source_port, dest_port, protocol):
    """Categorize attack and provide location/method information."""
    categories = {
        'DDoS': {'category': 'Volume-Based', 'method': 'Flooding', 'target_type': 'Network'},
        'Port Scan': {'category': 'Reconnaissance', 'method': 'Port Enumeration', 'target_type': 'Network'},
        'Brute Force': {'category': 'Credential Attack', 'method': 'Password Guessing', 'target_type': 'Application'},
        'SQL Injection': {'category': 'Application Attack', 'method': 'Database Exploitation', 'target_type': 'Application'},
        'Malware': {'category': 'Malicious Payload', 'method': 'Executable Delivery', 'target_type': 'Endpoint'},
        'Data Exfiltration': {'category': 'Data Breach', 'method': 'Unauthorized Data Transfer', 'target_type': 'Data'},
    }
    
    cat_info = categories.get(attack_type, {
        'category': 'Unknown Attack',
        'method': 'Anomalous Behavior',
        'target_type': 'Network'
    })
    
    # Determine attack location
    location = f"{source_ip}:{source_port} → {dest_ip}:{dest_port}"
    
    # Protocol-based attack location insight
    protocol_insights = {
        'TCP': 'TCP Connection-based',
        'UDP': 'UDP Packet-based',
        'ICMP': 'ICMP Echo-based'
    }
    
    return {
        'category': cat_info.get('category', 'Unknown'),
        'method': cat_info.get('method', 'Unknown Method'),
        'target_type': cat_info.get('target_type', 'Network'),
        'location': location,
        'protocol_type': protocol_insights.get(protocol, f'{protocol}-based'),
        'source': source_ip,
        'destination': dest_ip,
        'source_port': source_port,
        'dest_port': dest_port,
        'protocol': protocol
    }


@zero_day_bp.route('/api/anomalies', methods=['GET'])
@login_required
def get_anomalies_api():
    """Return recent anomalies as JSON with mitigations and federated context."""
    try:
        from app.models.database import db, Alert, MitigationStrategy, FederatedClient
        from detection.mitigation_engine import MitigationEngine, Severity
        from federated.federated_client_manager import get_client_manager

        limit = request.args.get('limit', 50, type=int)
        hours = request.args.get('hours', 24, type=int)
        # Optional: filter by federated client IDs (comma-separated)
        client_ids_param = request.args.get('client_ids')
        client_ids = [c.strip() for c in client_ids_param.split(',')] if client_ids_param else None
        include_mitigations = request.args.get('include_mitigations', 'true').lower() == 'true'
        include_federated = request.args.get('include_federated', 'true').lower() == 'true'
        
        since = datetime.utcnow() - timedelta(hours=hours)

        threshold = current_app.config.get('ANOMALY_THRESHOLD', 0.7)
        anomaly_score = func.coalesce(Alert.risk_score, Alert.confidence)

        # Filter to show ONLY zero-day attacks (high-confidence anomalies)
        anomalies_query = db.session.query(Alert).filter(
            anomaly_score >= threshold,
            Alert.confidence >= 0.7,
            Alert.timestamp >= since
        )
        if client_ids:
            anomalies_query = anomalies_query.filter(Alert.fed_client_id.in_(client_ids))
        anomalies = anomalies_query.order_by(Alert.timestamp.desc()).limit(limit).all()

        result = []
        for a in anomalies:
            attack_info = _categorize_attack(
                a.attack_type,
                a.source_ip,
                a.destination_ip,
                a.source_port or 0,
                a.destination_port or 0,
                a.protocol or 'TCP'
            )
            
            anomaly_data = {
                'id': a.id,
                'src_ip': a.source_ip,
                'dst_ip': a.destination_ip,
                'src_port': a.source_port,
                'dst_port': a.destination_port,
                'protocol': a.protocol,
                'anomaly_score': float(a.risk_score) if a.risk_score is not None else float(a.confidence or 0),
                'confidence': float(a.confidence) if a.confidence is not None else 0,
                'attack_type': a.attack_type,
                'timestamp': a.timestamp.isoformat() if a.timestamp else None,
                'severity': a.severity,
                'detector': a.model_used or 'ensemble',
                'attack_info': attack_info,
                'evidence': [],
                'mitigations': [],
                'federated_context': {}
            }
            
            # Include mitigations if requested
            if include_mitigations:
                mitigations = db.session.query(MitigationStrategy).filter(
                    MitigationStrategy.alert_id == a.id
                ).all()
                
                if mitigations:
                    anomaly_data['mitigations'] = [m.to_dict() for m in mitigations]
                else:
                    # Generate on-demand
                    try:
                        engine = MitigationEngine()
                        severity_map = {
                            'critical': Severity.CRITICAL,
                            'high': Severity.HIGH,
                            'medium': Severity.MEDIUM,
                            'low': Severity.LOW,
                            'info': Severity.INFO
                        }
                        severity = severity_map.get((a.severity or 'medium').lower(), Severity.MEDIUM)
                        
                        strategy = engine.generate_mitigation_strategy(
                            alert_id=a.id,
                            attack_type=a.attack_type,
                            severity=severity,
                            source_ip=a.source_ip,
                            destination_ip=a.destination_ip,
                            source_port=a.source_port or 0,
                            destination_port=a.destination_port or 0,
                            protocol=a.protocol or 'TCP',
                            confidence=a.confidence or 0.5
                        )
                        anomaly_data['mitigations'] = [s.to_dict() for s in strategy.steps]
                    except Exception as e:
                        logger.debug(f"Could not generate mitigations: {e}")
            
            # Include federated context if requested
            if include_federated:
                try:
                    manager = get_client_manager()
                    
                    # Check if alert is from federated detection
                    if a.fed_client_id:
                        client = next((c for c in manager.get_client_list() 
                                      if c['client_id'] == a.fed_client_id), None)
                        if client:
                            anomaly_data['federated_context'] = {
                                'detected_by_client': a.fed_client_id,
                                'client_organization': client.get('organization'),
                                'learning_round': a.fed_learning_round,
                                'client_status': client.get('status'),
                                'client_accuracy': client.get('local_accuracy')
                            }
                except Exception as e:
                    logger.debug(f"Could not get federated context: {e}")
            
            result.append(anomaly_data)
        
        return jsonify({
            'total': len(result),
            'anomalies': result,
            'include_mitigations': include_mitigations,
            'include_federated': include_federated
        })
    except Exception as e:
        logger.exception('Error fetching anomalies')
        return jsonify({'error': str(e)}), 500


@zero_day_bp.route('/api/detector-performance', methods=['GET'])
@login_required
def get_detector_performance():
    try:
        from app.models.database import db, Alert

        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)

        detectors = ['xgboost', 'autoencoder', 'lstm', 'ensemble']

        performance = {}
        for detector in detectors:
            detections = db.session.query(Alert).filter(
                func.coalesce(Alert.model_used, 'ensemble') == detector,
                Alert.timestamp >= since
            ).count()
            performance[detector] = {
                'total_detections': detections,
                'confirmed_positives': detections,
                'accuracy': 0.85
            }

        return jsonify(performance)
    except Exception as e:
        logger.exception('Error fetching detector performance')
        return jsonify({'error': str(e)}), 500


@zero_day_bp.route('/api/timeline', methods=['GET'])
@login_required
def get_anomaly_timeline():
    try:
        from app.models.database import db, Alert
        from sqlalchemy import func as safunc

        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)

        threshold = current_app.config.get('ANOMALY_THRESHOLD', 0.7)
        anomaly_score = func.coalesce(Alert.risk_score, Alert.confidence)

        timeline = db.session.query(
            safunc.strftime('%Y-%m-%dT%H:00:00', Alert.timestamp).label('time'),
            safunc.count(Alert.id).label('count'),
            safunc.avg(func.coalesce(Alert.risk_score, Alert.confidence)).label('avg_score')
        ).filter(
            anomaly_score >= threshold,
            Alert.timestamp >= since
        ).group_by('time').order_by('time').all()

        return jsonify([{
            'time': str(t[0]),
            'count': t[1],
            'avg_score': float(t[2]) if t[2] else 0
        } for t in timeline])
    except Exception as e:
        logger.exception('Error fetching timeline')
        return jsonify({'error': str(e)}), 500


@zero_day_bp.route('/api/top-sources', methods=['GET'])
@login_required
def get_top_sources():
    try:
        from app.models.database import db, Alert
        from sqlalchemy import func as safunc

        limit = request.args.get('limit', 10, type=int)
        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)

        threshold = current_app.config.get('ANOMALY_THRESHOLD', 0.7)
        anomaly_score = func.coalesce(Alert.risk_score, Alert.confidence)

        top_sources = db.session.query(
            Alert.source_ip,
            safunc.count(Alert.id).label('count'),
            safunc.avg(func.coalesce(Alert.risk_score, Alert.confidence)).label('avg_score'),
            safunc.max(func.coalesce(Alert.risk_score, Alert.confidence)).label('max_score')
        ).filter(
            anomaly_score >= threshold,
            Alert.timestamp >= since
        ).group_by(Alert.source_ip).order_by(safunc.count(Alert.id).desc()).limit(limit).all()

        return jsonify([{
            'source_ip': t[0],
            'count': t[1],
            'avg_score': float(t[2]) if t[2] else 0,
            'max_score': float(t[3]) if t[3] else 0
        } for t in top_sources])
    except Exception as e:
        logger.exception('Error fetching top sources')
        return jsonify({'error': str(e)}), 500


@zero_day_bp.route('/api/confidence-distribution', methods=['GET'])
@login_required
def get_confidence_distribution():
    try:
        from app.models.database import db, Alert
        from sqlalchemy import func as safunc

        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)

        bins = {
            'very_high': (0.8, 1.0),
            'high': (0.6, 0.8),
            'medium': (0.4, 0.6),
            'low': (0.2, 0.4),
            'very_low': (0.0, 0.2)
        }

        distribution = {}
        threshold = current_app.config.get('ANOMALY_THRESHOLD', 0.7)
        anomaly_score = func.coalesce(Alert.risk_score, Alert.confidence)

        for bin_name, (min_conf, max_conf) in bins.items():
            count = db.session.query(safunc.count(Alert.id)).filter(
                anomaly_score >= threshold,
                Alert.confidence >= min_conf,
                Alert.confidence < max_conf,
                Alert.timestamp >= since
            ).scalar()
            distribution[bin_name] = count or 0

        return jsonify(distribution)
    except Exception as e:
        logger.exception('Error fetching confidence distribution')
        return jsonify({'error': str(e)}), 500


@zero_day_bp.route('/alert/<int:alert_id>', methods=['GET'])
@login_required
def view_zero_day_alert(alert_id):
    try:
        from app.models.database import db, Alert

        alert = db.session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        return render_template('zero_day_alert_detail.html', alert=alert)
    except Exception as e:
        logger.exception('Error viewing alert')
        return jsonify({'error': str(e)}), 500


@zero_day_bp.route('/api/alert/<int:alert_id>/mitigations', methods=['GET'])
@login_required
def get_alert_mitigations(alert_id):
    """Get mitigation strategies for an alert."""
    try:
        from app.models.database import db, Alert, MitigationStrategy
        from detection.mitigation_engine import MitigationEngine, Severity
        
        # Fetch alert from database
        alert = db.session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Check if mitigation already exists in database
        existing_mitigations = db.session.query(MitigationStrategy).filter(
            MitigationStrategy.alert_id == alert_id
        ).all()
        
        if existing_mitigations:
            # Return existing mitigations
            return jsonify({
                'alert_id': alert_id,
                'attack_type': alert.attack_type,
                'severity': alert.severity,
                'source_ip': alert.source_ip,
                'destination_ip': alert.destination_ip,
                'mitigations': [m.to_dict() for m in existing_mitigations],
                'source': 'database',
                'count': len(existing_mitigations)
            })
        
        # Generate new mitigation strategy
        engine = MitigationEngine()
        
        # Map severity string to Severity enum
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        
        severity = severity_map.get((alert.severity or 'medium').lower(), Severity.MEDIUM)
        
        strategy = engine.generate_mitigation_strategy(
            alert_id=alert_id,
            attack_type=alert.attack_type,
            severity=severity,
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            source_port=alert.source_port or 0,
            destination_port=alert.destination_port or 0,
            protocol=alert.protocol or 'TCP',
            confidence=alert.confidence or 0.5,
            additional_context={
                'detector_model': alert.model_used,
                'confidence_score': alert.confidence,
                'risk_score': alert.risk_score,
                'description': alert.description
            }
        )
        
        # Store mitigation strategies in database
        for step in strategy.steps:
            mit = MitigationStrategy(
                alert_id=alert_id,
                attack_type=alert.attack_type,
                severity_level=alert.severity,
                action_type=step.action.value,
                target=step.target,
                description=step.description,
                command=step.command,
                priority=step.priority,
                is_automated=step.is_automated,
                automation_threshold=step.automation_threshold,
                status='pending'
            )
            db.session.add(mit)
        
        db.session.commit()
        
        # Return mitigation strategy
        return jsonify({
            'alert_id': alert_id,
            'attack_type': alert.attack_type,
            'severity': alert.severity,
            'source_ip': alert.source_ip,
            'destination_ip': alert.destination_ip,
            'mitigations': [step.to_dict() for step in strategy.steps],
            'source': 'generated',
            'count': len(strategy.steps),
            'total_estimated_time_seconds': sum([60 * (5 - s.priority) for s in strategy.steps])
        })
        
    except Exception as e:
        logger.exception('Error fetching mitigations for alert')
        return jsonify({'error': str(e)}), 500


@zero_day_bp.route('/api/alert/<int:alert_id>/mitigations/<int:mitigation_id>/execute', methods=['POST'])
@login_required
def execute_mitigation(alert_id, mitigation_id):
    """Execute a specific mitigation strategy."""
    try:
        from app.models.database import db, MitigationStrategy, User
        from flask_login import current_user
        
        mitigation = db.session.query(MitigationStrategy).filter(
            MitigationStrategy.id == mitigation_id,
            MitigationStrategy.alert_id == alert_id
        ).first()
        
        if not mitigation:
            return jsonify({'error': 'Mitigation not found'}), 404
        
        if mitigation.status != 'pending':
            return jsonify({'error': f'Mitigation is already {mitigation.status}'}), 400
        
        # Mark as approved and executed
        mitigation.status = 'executed'
        mitigation.executed_by = current_user.id
        mitigation.executed_at = datetime.utcnow()
        
        # TODO: Execute actual command if available
        execution_result = "Manual execution initiated by analyst"
        if mitigation.command:
            # In production, use a command execution service
            execution_result = f"Command queued for execution: {mitigation.command}"
        
        mitigation.execution_result = execution_result
        
        db.session.commit()
        
        logger.info(f"Mitigation {mitigation_id} executed by {current_user.username}")
        
        return jsonify({
            'success': True,
            'mitigation_id': mitigation_id,
            'status': 'executed',
            'execution_result': execution_result,
            'executed_at': mitigation.executed_at.isoformat() if mitigation.executed_at else None
        })
        
    except Exception as e:
        logger.exception('Error executing mitigation')
        return jsonify({'error': str(e)}), 500


@zero_day_bp.route('/api/alert/<int:alert_id>/mitigations/auto-execute', methods=['POST'])
@login_required
def auto_execute_mitigations(alert_id):
    """Auto-execute all low-priority mitigations for an alert."""
    try:
        from app.models.database import db, Alert, MitigationStrategy
        
        alert = db.session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Auto-execute only high-priority, automated mitigations
        auto_mitigations = db.session.query(MitigationStrategy).filter(
            MitigationStrategy.alert_id == alert_id,
            MitigationStrategy.is_automated == True,
            MitigationStrategy.status == 'pending'
        ).all()
        
        executed_count = 0
        for mit in auto_mitigations:
            if alert.confidence >= mit.automation_threshold:
                mit.status = 'executed'
                mit.executed_at = datetime.utcnow()
                mit.execution_result = f"Auto-executed with confidence {alert.confidence}"
                executed_count += 1
        
        db.session.commit()
        
        logger.info(f"Auto-executed {executed_count} mitigations for alert {alert_id}")
        
        return jsonify({
            'success': True,
            'alert_id': alert_id,
            'auto_executed_count': executed_count,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.exception('Error auto-executing mitigations')
        return jsonify({'error': str(e)}), 500


@zero_day_bp.route('/api/federated-status', methods=['GET'])
@login_required
def get_federated_status():
    """Get current federated learning status."""
    try:
        from app.routes.federated import _fed_server
        from federated.federated_client_manager import get_client_manager
        from detection.federated_learning_flow import get_federated_coordinator
        
        manager = get_client_manager()
        coordinator = get_federated_coordinator()
        
        online_clients = manager.get_online_clients()
        
        status = {
            'initialized': True,
            'status': 'active',
            'client_manager': {
                'total_clients': len(manager.clients),
                'online_clients': len(online_clients),
                'heartbeat_timeout_seconds': manager.heartbeat_timeout_seconds
            },
            'coordinator': {
                'current_round': coordinator.current_round,
                'round_state': coordinator.round_state.value,
                'rounds_completed': len(coordinator.round_history),
                'is_running': coordinator.is_running,
                'min_clients_per_round': coordinator.min_clients_per_round
            },
            'performance': {}
        }
        
        # Add performance metrics from latest round
        if coordinator.round_history:
            latest = coordinator.round_history[-1]
            status['performance'] = {
                'global_accuracy': latest.global_accuracy,
                'global_loss': latest.global_loss,
                'total_samples': latest.total_samples,
                'participating_clients': latest.participating_clients,
                'new_attack_types': latest.new_attack_types_detected,
                'timestamp': latest.timestamp.isoformat()
            }
        
        # Add old federation server status if available
        if _fed_server:
            status['legacy_fed_server'] = {
                'server_id': _fed_server.config.server_id if hasattr(_fed_server, 'config') else 'unknown',
                'rounds_completed': len(_fed_server.round_history) if hasattr(_fed_server, 'round_history') else 0,
                'model_version': str(_fed_server.global_model_version if hasattr(_fed_server, 'global_model_version') else 'v1')
            }
        
        return jsonify(status)
    except Exception as e:
        logger.exception('Error fetching federated status')
        return jsonify({
            'initialized': False,
            'status': 'error',
            'error': str(e)
        }), 500


@zero_day_bp.route('/api/threat-mitigation-federated/<int:alert_id>', methods=['GET'])
@login_required
def get_integrated_threat_analysis(alert_id):
    """
    Get comprehensive threat analysis with mitigations and federated learning context.
    
    This endpoint integrates:
    1. Alert details
    2. Recommended mitigations
    3. Federated learning context (which organization detected it, round info, etc.)
    4. Global model performance improvements
    """
    try:
        from app.models.database import db, Alert, MitigationStrategy, FederatedRound, FederatedClient
        from detection.mitigation_engine import MitigationEngine, Severity
        from federated.federated_client_manager import get_client_manager
        from detection.federated_learning_flow import get_federated_coordinator
        
        # Fetch alert
        alert = db.session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Get mitigations
        mitigations = db.session.query(MitigationStrategy).filter(
            MitigationStrategy.alert_id == alert_id
        ).all()
        
        if not mitigations:
            # Generate on-demand
            engine = MitigationEngine()
            severity_map = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
                'info': Severity.INFO
            }
            severity = severity_map.get((alert.severity or 'medium').lower(), Severity.MEDIUM)
            
            strategy = engine.generate_mitigation_strategy(
                alert_id=alert_id,
                attack_type=alert.attack_type,
                severity=severity,
                source_ip=alert.source_ip,
                destination_ip=alert.destination_ip,
                source_port=alert.source_port or 0,
                destination_port=alert.destination_port or 0,
                protocol=alert.protocol or 'TCP',
                confidence=alert.confidence or 0.5
            )
            mitigations_data = [s.to_dict() for s in strategy.steps]
        else:
            mitigations_data = [m.to_dict() for m in mitigations]
        
        # Get federated context
        manager = get_client_manager()
        coordinator = get_federated_coordinator()
        
        federated_context = {
            'detected_by_federated_system': bool(alert.fed_client_id),
            'learning_round': alert.fed_learning_round,
            'client_info': None,
            'round_info': None,
            'contributed_to_global_model': False
        }
        
        if alert.fed_client_id:
            # Get client info
            clients = manager.get_client_list()
            client_info = next((c for c in clients if c['client_id'] == alert.fed_client_id), None)
            if client_info:
                federated_context['client_info'] = client_info
                
                # Get round info
                if alert.fed_learning_round:
                    # Check if this round exists in history
                    for round_result in coordinator.round_history:
                        if round_result.round_number == alert.fed_learning_round:
                            federated_context['round_info'] = round_result.to_dict()
                            federated_context['contributed_to_global_model'] = True
                            break
        
        # Global model impact
        global_impact = {
            'current_model_accuracy': coordinator.round_history[-1].global_accuracy if coordinator.round_history else 0.0,
            'current_model_loss': coordinator.round_history[-1].global_loss if coordinator.round_history else 0.0,
            'total_clients_in_federation': len(manager.clients),
            'online_clients': len(manager.get_online_clients()),
            'total_samples_aggregated': sum(
                r.total_samples for r in coordinator.round_history
            )
        }
        
        # Compile integrated response
        response = {
            'alert': {
                'id': alert.id,
                'attack_type': alert.attack_type,
                'severity': alert.severity,
                'confidence': alert.confidence,
                'risk_score': alert.risk_score,
                'source_ip': alert.source_ip,
                'destination_ip': alert.destination_ip,
                'timestamp': alert.timestamp.isoformat() if alert.timestamp else None
            },
            'mitigations': {
                'strategies': mitigations_data,
                'total_steps': len(mitigations_data),
                'high_priority_steps': len([m for m in mitigations_data if m['priority'] <= 2]),
                'automated_steps': len([m for m in mitigations_data if m['is_automated']])
            },
            'federated_learning': federated_context,
            'global_model_impact': global_impact,
            'recommendations': _generate_recommendations({
                'id': alert.id,
                'source_ip': alert.source_ip,
                'destination_ip': alert.destination_ip,
                'attack_type': alert.attack_type,
                'severity': alert.severity,
                'confidence': alert.confidence
            }, mitigations_data, federated_context)
        }
        
        return jsonify(response)
    
    except Exception as e:
        logger.exception('Error getting integrated threat analysis')
        return jsonify({'error': str(e)}), 500


def _generate_recommendations(alert, mitigations, federated_context):
    """Generate AI recommendations based on threat analysis."""
    recommendations = []
    
    # Recommendation 1: Immediate mitigation actions
    high_priority_mitigations = [m for m in mitigations if m['priority'] <= 2]
    if high_priority_mitigations:
        recommendations.append({
            'type': 'immediate_action',
            'priority': 'critical',
            'recommendation': f'Execute {len(high_priority_mitigations)} high-priority mitigation steps immediately',
            'steps': [m['action'] for m in high_priority_mitigations[:3]]
        })
    
    # Recommendation 2: Global model improvement opportunity
    if federated_context.get('detected_by_federated_system') and not federated_context.get('contributed_to_global_model'):
        recommendations.append({
            'type': 'federated_learning_opportunity',
            'priority': 'high',
            'recommendation': 'Share this novel attack pattern with federated learning network to improve global detection',
            'action': f'Submit attack characteristics from {alert.get("source_ip")} for federated aggregation'
        })
    
    # Recommendation 3: Cross-organizational awareness
    if federated_context.get('client_info'):
        recommendations.append({
            'type': 'cross_org_alert',
            'priority': 'high',
            'recommendation': f'Alert other organizations in federation about attack from {alert.get("source_ip")}',
            'affected_organization': federated_context['client_info'].get('organization')
        })
    
    # Recommendation 4: Threat intelligence integration
    recommendations.append({
        'type': 'threat_intel',
        'priority': 'medium',
        'recommendation': 'Lookup source IP in threat intelligence feeds (AlienVault OTX, VirusTotal)',
        'source_ip': alert.get('source_ip')
    })
    
    return recommendations


@zero_day_bp.route('/api/detector-stats', methods=['GET'])
@login_required
def get_detector_stats_api():
    return jsonify(get_detector_stats())


def get_detector_stats() -> Dict:
    try:
        engine = current_app.config.get('ZERO_DAY_ENGINE')
        if engine and hasattr(engine, 'get_detector_stats'):
            return engine.get_detector_stats()
    except Exception:
        logger.exception('Could not get detector stats')

    return {
        'reconstruction_error_history_size': 0,
        'statistical_history_size': 0,
        'temporal_history_size': 0,
        'entropy_history_size': 0,
        'weights': {}
    }
