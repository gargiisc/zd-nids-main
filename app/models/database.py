"""
Database Models
===============
SQLAlchemy ORM models for AI-NIDS application.
"""

from datetime import datetime
import secrets
import json
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

from app import db


class User(UserMixin, db.Model):
    """User model for authentication."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='analyst')  # admin, analyst, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    api_keys = db.relationship('APIKey', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        """Hash and set password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash."""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
    
    def __repr__(self):
        return f'<User {self.username}>'


class Alert(db.Model):
    """Alert model for detected threats."""
    
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Network Information
    source_ip = db.Column(db.String(45), index=True)  # IPv6 compatible
    destination_ip = db.Column(db.String(45), index=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    
    # Detection Information
    attack_type = db.Column(db.String(100), index=True)
    severity = db.Column(db.String(20), index=True)  # critical, high, medium, low, info
    confidence = db.Column(db.Float)  # 0.0 to 1.0
    risk_score = db.Column(db.Float)  # Ensemble score
    
    # Description
    description = db.Column(db.Text)
    
    # Model Information
    model_used = db.Column(db.String(50))  # xgboost, autoencoder, lstm, ensemble
    shap_values = db.Column(db.Text)  # JSON string of SHAP explanations
    
    # Status
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    acknowledged_at = db.Column(db.DateTime)
    
    resolved = db.Column(db.Boolean, default=False)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    resolved_at = db.Column(db.DateTime)
    resolution_notes = db.Column(db.Text)
    
    # Raw Data
    raw_data = db.Column(db.Text)  # JSON string of original flow data
    
    # Mitigation Information
    mitigation_strategies = db.Column(db.Text)  # JSON array of mitigation strategies
    mitigation_applied = db.Column(db.Boolean, default=False)
    mitigation_timestamp = db.Column(db.DateTime)
    
    # Federated Learning Context
    fed_learning_round = db.Column(db.Integer)  # Which federated round detected this
    fed_client_id = db.Column(db.String(100))  # Which federated client detected it
    
    # Indexes for performance
    __table_args__ = (
        db.Index('idx_alert_severity_timestamp', 'severity', 'timestamp'),
        db.Index('idx_alert_type_timestamp', 'attack_type', 'timestamp'),
    )
    
    def to_dict(self, include_explanation=False):
        """Convert to dictionary."""
        data = {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'attack_type': self.attack_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'risk_score': self.risk_score,
            'description': self.description,
            'model_used': self.model_used,
            'acknowledged': self.acknowledged,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved': self.resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolution_notes': self.resolution_notes
        }
        
        if include_explanation and self.shap_values:
            try:
                data['explanation'] = json.loads(self.shap_values)
            except:
                data['explanation'] = None
        
        return data
    
    @property
    def severity_color(self):
        """Get Bootstrap color class for severity."""
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'secondary',
            'info': 'light'
        }
        return colors.get(self.severity, 'secondary')
    
    @property
    def severity_icon(self):
        """Get icon for severity."""
        icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'info': '🔵'
        }
        return icons.get(self.severity, '⚪')
    
    def __repr__(self):
        return f'<Alert {self.id} - {self.attack_type} ({self.severity})>'


class NetworkFlow(db.Model):
    """Network flow model for traffic data."""
    
    __tablename__ = 'network_flows'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Network Information
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45), index=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer, index=True)
    protocol = db.Column(db.String(20))
    
    # Flow Statistics
    duration = db.Column(db.Float)
    total_bytes = db.Column(db.BigInteger)
    packets_sent = db.Column(db.Integer)
    packets_recv = db.Column(db.Integer)
    bytes_sent = db.Column(db.BigInteger)
    bytes_recv = db.Column(db.BigInteger)
    
    # Flags
    syn_count = db.Column(db.Integer, default=0)
    ack_count = db.Column(db.Integer, default=0)
    fin_count = db.Column(db.Integer, default=0)
    rst_count = db.Column(db.Integer, default=0)
    
    # Classification
    label = db.Column(db.String(50))  # BENIGN, DoS, DDoS, etc.
    predicted_label = db.Column(db.String(50))
    is_anomaly = db.Column(db.Boolean, default=False)
    
    # Raw Data
    raw_data = db.Column(db.Text)  # JSON string
    
    # Indexes for performance
    __table_args__ = (
        db.Index('idx_flow_timestamp', 'timestamp'),
        db.Index('idx_flow_src_dst', 'source_ip', 'destination_ip'),
    )
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'duration': self.duration,
            'total_bytes': self.total_bytes,
            'packets_sent': self.packets_sent,
            'packets_recv': self.packets_recv,
            'label': self.label,
            'predicted_label': self.predicted_label
        }
    
    def __repr__(self):
        return f'<NetworkFlow {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}>'


class APIKey(db.Model):
    """API Key model for external integrations."""
    
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    
    @classmethod
    def generate_key(cls, user_id, name='API Key', expires_days=None):
        """Generate a new API key."""
        key = secrets.token_hex(32)
        
        api_key = cls(
            key=key,
            name=name,
            user_id=user_id
        )
        
        if expires_days:
            from datetime import timedelta
            api_key.expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        return api_key
    
    def is_valid(self):
        """Check if key is valid."""
        if not self.is_active:
            return False
        
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        
        return True
    
    def to_dict(self):
        """Convert to dictionary (without full key)."""
        return {
            'id': self.id,
            'name': self.name,
            'key_prefix': self.key[:8] + '...' if self.key else None,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }
    
    def __repr__(self):
        return f'<APIKey {self.name}>'


class SystemMetrics(db.Model):
    """System metrics for monitoring."""
    
    __tablename__ = 'system_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Processing Metrics
    flows_processed = db.Column(db.Integer, default=0)
    alerts_generated = db.Column(db.Integer, default=0)
    processing_time_ms = db.Column(db.Float)
    
    # System Metrics
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    disk_usage = db.Column(db.Float)
    
    # Model Metrics
    model_inference_time_ms = db.Column(db.Float)
    model_accuracy = db.Column(db.Float)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'flows_processed': self.flows_processed,
            'alerts_generated': self.alerts_generated,
            'processing_time_ms': self.processing_time_ms,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'disk_usage': self.disk_usage,
            'model_inference_time_ms': self.model_inference_time_ms
        }
    
    def __repr__(self):
        return f'<SystemMetrics {self.timestamp}>'


class ThreatIntelligence(db.Model):
    """Threat intelligence data."""
    
    __tablename__ = 'threat_intelligence'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, index=True)
    threat_type = db.Column(db.String(50))
    confidence = db.Column(db.Float)
    source = db.Column(db.String(50))  # AbuseIPDB, VirusTotal, etc.
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    is_blocked = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    raw_data = db.Column(db.Text)  # JSON from source
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'threat_type': self.threat_type,
            'confidence': self.confidence,
            'source': self.source,
            'is_blocked': self.is_blocked,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }
    
    def __repr__(self):
        return f'<ThreatIntelligence {self.ip_address}>'


class MitigationStrategy(db.Model):
    """Mitigation strategies for detected threats."""
    
    __tablename__ = 'mitigation_strategies'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), index=True)
    
    # Mitigation Details
    attack_type = db.Column(db.String(100), index=True)
    severity_level = db.Column(db.String(20))  # critical, high, medium, low
    
    # Mitigation Actions
    action_type = db.Column(db.String(50))  # block_ip, rate_limit, isolate, patch, etc.
    target = db.Column(db.String(255))  # IP, port, service, hostname
    description = db.Column(db.Text)
    
    # Implementation Details
    command = db.Column(db.Text)  # Actual command/action to execute
    priority = db.Column(db.Integer, default=1)  # 1=highest, 10=lowest
    
    # Status
    status = db.Column(db.String(20), default='pending')  # pending, approved, executed, rolled_back
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    approved_at = db.Column(db.DateTime)
    
    executed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    executed_at = db.Column(db.DateTime)
    execution_result = db.Column(db.Text)
    
    # Automatic vs Manual
    is_automated = db.Column(db.Boolean, default=False)
    automation_threshold = db.Column(db.Float)  # Confidence threshold for auto-execution
    
    # Effectiveness
    effectiveness_score = db.Column(db.Float)  # 0.0 to 1.0
    notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'attack_type': self.attack_type,
            'severity_level': self.severity_level,
            'action_type': self.action_type,
            'target': self.target,
            'description': self.description,
            'priority': self.priority,
            'status': self.status,
            'is_automated': self.is_automated,
            'effectiveness_score': self.effectiveness_score,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'notes': self.notes
        }
    
    def __repr__(self):
        return f'<MitigationStrategy {self.action_type} for {self.attack_type}>'


class FederatedClient(db.Model):
    """Federated Learning Clients."""
    
    __tablename__ = 'federated_clients'
    
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(100), unique=True, index=True)
    organization = db.Column(db.String(255), index=True)
    subnet = db.Column(db.String(50))  # CIDR notation
    
    # Connection Details
    server_url = db.Column(db.String(255))
    api_key = db.Column(db.String(256))
    
    # Status
    is_active = db.Column(db.Boolean, default=True, index=True)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_heartbeat = db.Column(db.DateTime)
    last_training_round = db.Column(db.DateTime)
    
    # Statistics
    total_flows_seen = db.Column(db.Integer, default=0)
    total_attacks_detected = db.Column(db.Integer, default=0)
    total_training_rounds = db.Column(db.Integer, default=0)
    
    # Model Performance
    local_accuracy = db.Column(db.Float)
    local_precision = db.Column(db.Float)
    local_recall = db.Column(db.Float)
    
    # Privacy Metrics
    epsilon_spent = db.Column(db.Float, default=0.0)  # Differential privacy budget
    
    # Metadata
    client_metadata = db.Column(db.Text)  # JSON: version info, hardware, etc.
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'client_id': self.client_id,
            'organization': self.organization,
            'subnet': self.subnet,
            'is_active': self.is_active,
            'registered_at': self.registered_at.isoformat() if self.registered_at else None,
            'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            'last_training_round': self.last_training_round.isoformat() if self.last_training_round else None,
            'total_flows_seen': self.total_flows_seen,
            'total_attacks_detected': self.total_attacks_detected,
            'total_training_rounds': self.total_training_rounds,
            'local_accuracy': self.local_accuracy,
            'local_precision': self.local_precision,
            'local_recall': self.local_recall,
            'epsilon_spent': self.epsilon_spent,
            'status': 'online' if self.last_heartbeat and (datetime.utcnow() - self.last_heartbeat).seconds < 300 else 'offline'
        }
    
    def is_online(self):
        """Check if client is currently online."""
        if not self.last_heartbeat:
            return False
        return (datetime.utcnow() - self.last_heartbeat).total_seconds() < 300
    
    def __repr__(self):
        return f'<FederatedClient {self.client_id} - {self.organization}>'


class FederatedRound(db.Model):
    """Federated Learning Training Rounds."""
    
    __tablename__ = 'federated_rounds'
    
    id = db.Column(db.Integer, primary_key=True)
    round_number = db.Column(db.Integer, index=True)
    
    # Round Configuration
    started_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime)
    
    # Participation
    total_clients_invited = db.Column(db.Integer)
    total_clients_participated = db.Column(db.Integer)
    
    # Model Performance
    global_accuracy = db.Column(db.Float)
    global_loss = db.Column(db.Float)
    
    # Aggregation Stats
    total_samples_trained = db.Column(db.Integer)
    aggregation_strategy = db.Column(db.String(50))  # fedavg, fedprox, etc.
    
    # New Attack Types Detected
    new_attack_types = db.Column(db.Text)  # JSON array
    
    # Model Update
    model_version = db.Column(db.String(50))
    model_hash = db.Column(db.String(64))
    
    status = db.Column(db.String(20))  # in_progress, completed, failed
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'round_number': self.round_number,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_clients_invited': self.total_clients_invited,
            'total_clients_participated': self.total_clients_participated,
            'global_accuracy': self.global_accuracy,
            'global_loss': self.global_loss,
            'total_samples_trained': self.total_samples_trained,
            'aggregation_strategy': self.aggregation_strategy,
            'model_version': self.model_version,
            'status': self.status
        }
    
    def __repr__(self):
        return f'<FederatedRound {self.round_number} - {self.status}>'
