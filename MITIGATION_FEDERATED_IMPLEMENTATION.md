# AI-NIDS: Mitigation Techniques & Real-Time Federated Learning Implementation

## Overview

This implementation adds three critical capabilities to AI-NIDS:

1. **Mitigation Techniques** - Attack-specific remediation strategies
2. **Real-Time Federated Learning** - Collaborative detection across organizations
3. **Architecture Diagram Integration** - Complete flow following the provided architecture

---

## 1. Mitigation Techniques (Tasks 1-3)

### Components Added

#### A. Database Models (`app/models/database.py`)
- **`MitigationStrategy` Model**: Stores mitigation steps for each alert
  - Action type (block IP, rate limit, isolate, patch, etc.)
  - Target (IP, port, service, hostname)
  - Priority and automation thresholds
  - Status tracking (pending, approved, executed)
  - Effectiveness scoring

- **Updated `Alert` Model**: 
  - Added `mitigation_strategies` field
  - Added `mitigation_applied` flag
  - Added federated learning context fields

#### B. Mitigation Engine (`detection/mitigation_engine.py`)
Generates intelligent mitigation strategies based on attack type and severity:

```python
from detection.mitigation_engine import MitigationEngine, Severity

engine = MitigationEngine()
strategy = engine.generate_mitigation_strategy(
    alert_id=123,
    attack_type='DDoS',
    severity=Severity.CRITICAL,
    source_ip='192.168.1.100',
    destination_ip='10.0.0.50',
    source_port=12345,
    destination_port=80,
    protocol='TCP',
    confidence=0.95
)

# Returns MitigationStrategy with prioritized steps
for step in strategy.steps:
    print(f"{step.priority}: {step.description}")
    if step.is_automated and confidence >= step.automation_threshold:
        execute(step.command)
```

**Attack-Type Mitigation Matrix:**
- **DDoS**: Block IP → Rate Limit → Monitor → Alert SOC
- **Port Scan**: Block IP → Monitor → Capture Traffic
- **Brute Force**: Block IP → Reset Credentials → Enable MFA → Alert
- **SQL Injection**: Update WAF → DPI → Isolate Host → Alert
- **Malware**: Isolate Host → Quarantine → Alert → Capture
- **Data Exfiltration**: Block IP → Deep Packet Inspection → Alert
- **Web Attack**: Update WAF → Monitor → Alert

### API Endpoints

#### Get Mitigations for an Alert
```bash
GET /zero-day/api/alert/{alert_id}/mitigations

Response:
{
    "alert_id": 123,
    "attack_type": "DDoS",
    "severity": "critical",
    "mitigations": [
        {
            "action": "block_ip",
            "target": "192.168.1.100",
            "description": "Block all traffic from/to 192.168.1.100",
            "priority": 1,
            "is_automated": true,
            "automation_threshold": 0.9,
            "requires_approval": true,
            "rollback_possible": true,
            "duration_hours": 24
        },
        ...
    ],
    "total_estimated_time_seconds": 300
}
```

#### Execute a Mitigation
```bash
POST /zero-day/api/alert/{alert_id}/mitigations/{mitigation_id}/execute

Response:
{
    "success": true,
    "mitigation_id": 456,
    "status": "executed",
    "executed_at": "2026-01-26T10:30:00Z"
}
```

#### Auto-Execute Low-Risk Mitigations
```bash
POST /zero-day/api/alert/{alert_id}/mitigations/auto-execute

Response:
{
    "success": true,
    "auto_executed_count": 3,
    "timestamp": "2026-01-26T10:30:00Z"
}
```

---

## 2. Real-Time Federated Learning (Tasks 4-6)

### Architecture Diagram Flow

```
Detector 0 (Hospital)      Detector 1 (Bank)      Detector N (Utility)
    ↓                          ↓                           ↓
[Model Update]           [Model Update]           [Model Update]
[Incremental Learning]   [Incremental Learning]   [Incremental Learning]
    ↓                          ↓                           ↓
[Upload Learned Parameters]  [Upload]              [Upload]
    ↓                          ↓                           ↓
    └──────────────────→ Global Aggregation Platform ←──────────────┘
                              ↓
                    [Aggregate Parameters]
                    [Generate Global Model]
                              ↓
    ┌──────────────────→ Broadcast Updated Model ←──────────────┐
    ↓                          ↓                           ↓
[Deploy]                  [Deploy]                  [Deploy]
[Online Detection]        [Online Detection]        [Online Detection]
Find new attacks          Find new attacks          Find new attacks
```

### Components Added

#### A. Federated Client Manager (`federated/federated_client_manager.py`)
Manages client registration, heartbeats, and model distribution:

```python
from federated.federated_client_manager import get_client_manager

manager = get_client_manager()

# Register a new client
result = manager.register_client(
    organization="Hospital A",
    subnet="192.168.1.0/24",
    server_url="http://hospital-a.local:8001"
)
# Returns: client_id, api_key, server_url

# Record heartbeat
manager.heartbeat(
    client_id="fed-abc123",
    flows_processed=1000,
    attacks_detected=5,
    model_version="v2.1",
    local_accuracy=0.96
)

# Get online clients
online = manager.get_online_clients()

# Distribute new model
manager.distribute_model_update(
    model_version="v2.2",
    model_hash="abc123def456",
    download_url="http://server:8080/models/v2.2"
)
```

**Key Features:**
- Real-time client registration
- Heartbeat monitoring (300s timeout)
- Automatic offline detection
- Model distribution queuing
- Background threads for async operations

#### B. Real-Time Federated Learning Coordinator (`detection/federated_learning_flow.py`)
Orchestrates training rounds and model aggregation:

```python
from detection.federated_learning_flow import get_federated_coordinator

coordinator = get_federated_coordinator()

# Clients submit gradient updates
coordinator.submit_gradient_update(
    client_id="fed-abc123",
    model_weights={...},  # Local model parameters
    gradients={...},      # Computed gradients
    training_metrics={
        'samples': 5000,
        'accuracy': 0.95,
        'loss': 0.15,
        'new_attacks': ['variant_of_zerofill']
    }
)

# Get coordinator status
status = coordinator.get_current_status()
# {
#     'current_round': 42,
#     'round_state': 'aggregating',
#     'rounds_completed': 41,
#     'latest_global_accuracy': 0.944,
#     'gradient_queue_size': 15
# }

# Get round history
history = coordinator.get_round_history(limit=10)
```

**Training Round Flow:**
1. **Initiate**: Round orchestrator starts new round
2. **Collect**: Clients send gradient updates for 60 seconds
3. **Aggregate**: FedAvg aggregation of gradients (weighted by samples)
4. **Distribute**: New global model pushed to all online clients
5. **Complete**: Round marked complete, stats recorded
6. **Repeat**: Continuous training rounds

#### C. Database Models for Federated Learning
- **`FederatedClient`**: Client registration and statistics
- **`FederatedRound`**: Training round history and metrics

### API Endpoints

#### Register Federated Client
```bash
POST /api/federated/register

Request:
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
```

#### Client Heartbeat
```bash
POST /api/federated/heartbeat

Request:
{
    "client_id": "fed-abc123",
    "flows_processed": 1000,
    "attacks_detected": 5,
    "model_version": "v2.1",
    "local_accuracy": 0.96
}

Response:
{
    "success": true,
    "message": "Heartbeat recorded",
    "server_timestamp": "2026-01-26T10:30:00Z"
}
```

#### Get Real-Time Clients Status
```bash
GET /api/federated/clients/real-time

Response:
{
    "total_clients": 42,
    "online_clients": 38,
    "clients": [
        {
            "client_id": "fed-abc123",
            "organization": "Hospital A",
            "subnet": "192.168.1.0/24",
            "status": "online",
            "total_flows_seen": 125000,
            "total_attacks_detected": 342,
            "local_accuracy": 0.96,
            "last_heartbeat": "2026-01-26T10:29:45Z"
        },
        ...
    ]
}
```

#### Distribute Model Update
```bash
POST /api/federated/distribute-model

Request:
{
    "model_version": "v2.2",
    "model_hash": "abc123def456",
    "download_url": "http://central-server:8080/models/v2.2",
    "target_clients": ["fed-abc123", "fed-xyz789"]
}

Response:
{
    "success": true,
    "task_id": "task-001",
    "model_version": "v2.2",
    "target_clients_count": 38,
    "status": "queued"
}
```

#### Get Federated Status
```bash
GET /api/federated-status

Response:
{
    "initialized": true,
    "status": "active",
    "client_manager": {
        "total_clients": 42,
        "online_clients": 38,
        "heartbeat_timeout_seconds": 300
    },
    "coordinator": {
        "current_round": 42,
        "round_state": "aggregating",
        "rounds_completed": 41,
        "is_running": true,
        "min_clients_per_round": 3
    },
    "performance": {
        "global_accuracy": 0.944,
        "global_loss": 0.12,
        "total_samples": 2100000,
        "participating_clients": 38,
        "new_attack_types": ["ransomware_variant_42", "iot_botnet_v3"]
    }
}
```

---

## 3. Integration: Mitigations + Federated Learning in Zero-Day Routes

### Enhanced Zero-Day Dashboard
```
GET /zero-day/

Includes:
- Zero-day alerts (24h)
- Federated learning stats:
  - Online/total clients
  - Current round number
  - Global model accuracy
  - New attack types detected
```

### Enhanced Anomalies API
```bash
GET /zero-day/api/anomalies?include_mitigations=true&include_federated=true

Response includes:
{
    "anomalies": [
        {
            "id": 123,
            "attack_type": "DDoS",
            "severity": "critical",
            "confidence": 0.95,
            "mitigations": [
                {
                    "action": "block_ip",
                    "target": "192.168.1.100",
                    "priority": 1,
                    "is_automated": true
                },
                ...
            ],
            "federated_context": {
                "detected_by_client": "fed-abc123",
                "client_organization": "Hospital A",
                "learning_round": 40,
                "client_status": "online",
                "client_accuracy": 0.96
            }
        }
    ]
}
```

### Comprehensive Threat-Mitigation-Federated Analysis
```bash
GET /zero-day/api/threat-mitigation-federated/{alert_id}

Response:
{
    "alert": {
        "id": 123,
        "attack_type": "DDoS",
        "severity": "critical",
        "confidence": 0.95,
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.50"
    },
    "mitigations": {
        "strategies": [...],
        "total_steps": 4,
        "high_priority_steps": 2,
        "automated_steps": 1
    },
    "federated_learning": {
        "detected_by_federated_system": true,
        "learning_round": 40,
        "client_info": {
            "client_id": "fed-abc123",
            "organization": "Hospital A",
            "status": "online"
        },
        "round_info": {
            "global_accuracy": 0.944,
            "participants": 38,
            "new_attacks": ["ddos_variant_99"]
        },
        "contributed_to_global_model": true
    },
    "global_model_impact": {
        "current_model_accuracy": 0.944,
        "total_clients_in_federation": 42,
        "online_clients": 38,
        "total_samples_aggregated": 2100000
    },
    "recommendations": [
        {
            "type": "immediate_action",
            "priority": "critical",
            "recommendation": "Execute 2 high-priority mitigation steps immediately",
            "steps": ["block_ip", "rate_limit"]
        },
        {
            "type": "cross_org_alert",
            "priority": "high",
            "recommendation": "Alert other organizations in federation about attack from 192.168.1.100",
            "affected_organization": "Hospital A"
        }
    ]
}
```

---

## 4. Architecture Diagram Compliance

The implementation follows the provided architecture diagram exactly:

### ✅ Detector Layer (Bottom)
- Each detector (Detector 0, N) represents a `FederatedClient`
- Detectors perform:
  - Model Updates (incremental learning on local data)
  - Deployment (updated model loaded locally)
  - Online Detection (real-time anomaly detection)
  - Find new attacks (zero-day detection)

### ✅ Gateway Layer (Middle)
- `FederatedClientManager` manages client registration and heartbeats
- Clients communicate via HTTP APIs (register, heartbeat, download model)

### ✅ Global Aggregation Platform (Top)
- `RealTimeFederatedLearningCoordinator` orchestrates training rounds
- Aggregation strategy: FedAvg (weighted average by samples)
- Distributes updated detection model back to all detectors
- Tracks attack distribution and new threats

### ✅ Real-Time Flow
1. **Detection**: Detectors find unknown attacks using ensemble models
2. **Training**: Local incremental learning on detected attacks
3. **Upload**: Gradient updates sent to coordinator
4. **Aggregation**: Global model updated via FedAvg
5. **Distribution**: Updated model pushed to all detectors
6. **Deployment**: Detectors deploy new model
7. **Repeat**: Continuous cycle for real-time adaptation

---

## 5. Usage Examples

### Example 1: Detect Attack + Get Mitigations + Check Federated Context
```python
from flask import Flask
from app.models.database import db, Alert

# Alert detected
alert_id = 123

# Get comprehensive analysis
# GET /zero-day/api/threat-mitigation-federated/123

# Response shows:
# - Alert details (source, destination, attack type)
# - Top-priority mitigations (block IP, rate limit)
# - Federated context (Hospital A detected it in round 40)
# - AI recommendations (share with federation, block IPs globally)
```

### Example 2: Register New Federated Client
```python
import requests

response = requests.post('http://localhost:8080/api/federated/register', json={
    'organization': 'Bank of Future',
    'subnet': '203.0.113.0/24',
    'server_url': 'http://bank.future.org:8001'
})

# Get credentials to join federation
client_id = response.json()['client_id']
api_key = response.json()['api_key']

# Now client can send heartbeats and gradient updates
```

### Example 3: Federated Learning Round Flow
```python
# Round 1: Detectors train locally
for detector in detectors:
    detector.train_locally()
    
# Round 2: Submit gradient updates
for detector in detectors:
    coordinator.submit_gradient_update(
        client_id=detector.id,
        model_weights=detector.model.weights,
        gradients=detector.compute_gradients(),
        training_metrics=detector.metrics
    )

# Round 3: Coordinator aggregates
# - Collects updates from all online detectors
# - Performs FedAvg aggregation
# - Records new attack types discovered
# - Distributes updated model

# Round 4: Detectors deploy new model
for detector in detectors:
    detector.download_global_model()
    detector.deploy_model()
    detector.resume_detection()
```

---

## 6. Database Schema Updates

### New Tables
```sql
CREATE TABLE mitigation_strategies (
    id INTEGER PRIMARY KEY,
    alert_id INTEGER FOREIGN KEY,
    attack_type VARCHAR,
    action_type VARCHAR,
    target VARCHAR,
    priority INTEGER,
    status VARCHAR,
    is_automated BOOLEAN,
    automation_threshold FLOAT,
    executed_at DATETIME,
    effectiveness_score FLOAT
);

CREATE TABLE federated_clients (
    id INTEGER PRIMARY KEY,
    client_id VARCHAR UNIQUE,
    organization VARCHAR,
    subnet VARCHAR,
    is_active BOOLEAN,
    registered_at DATETIME,
    last_heartbeat DATETIME,
    total_flows_seen INTEGER,
    total_attacks_detected INTEGER,
    local_accuracy FLOAT,
    epsilon_spent FLOAT
);

CREATE TABLE federated_rounds (
    id INTEGER PRIMARY KEY,
    round_number INTEGER,
    started_at DATETIME,
    completed_at DATETIME,
    total_clients_invited INTEGER,
    total_clients_participated INTEGER,
    global_accuracy FLOAT,
    global_loss FLOAT,
    total_samples_trained INTEGER,
    new_attack_types TEXT,
    status VARCHAR
);
```

### Updated Alert Table
```sql
ALTER TABLE alerts ADD COLUMN:
    mitigation_strategies TEXT,
    mitigation_applied BOOLEAN,
    mitigation_timestamp DATETIME,
    fed_learning_round INTEGER,
    fed_client_id VARCHAR
```

---

## 7. Configuration

No additional configuration needed. The system uses:
- Existing `config.py` settings
- Database connection string from `DATABASE_URL`
- Flask app initialization

To enable/disable components:
```python
# config.py
ENABLE_MITIGATIONS = True
ENABLE_FEDERATED_LEARNING = True
FEDERATED_MIN_CLIENTS_PER_ROUND = 3
FEDERATED_ROUND_DURATION_SECONDS = 300
```

---

## 8. Testing

### Test Mitigation Generation
```bash
curl -X GET http://localhost:5000/zero-day/api/alert/123/mitigations \
  -H "Authorization: Bearer <token>"
```

### Test Client Registration
```bash
curl -X POST http://localhost:5000/api/federated/register \
  -H "Content-Type: application/json" \
  -d '{
    "organization": "Test Org",
    "subnet": "10.0.0.0/24",
    "server_url": "http://test.local:8001"
  }'
```

### Test Federated Status
```bash
curl -X GET http://localhost:5000/api/federated-status \
  -H "Authorization: Bearer <token>"
```

---

## 9. Performance Considerations

- **Mitigations**: Generated on-demand (< 100ms)
- **Federated rounds**: 5-minute default duration (configurable)
- **Client heartbeats**: 300-second timeout (5 minutes)
- **Model distribution**: Async queue-based
- **Background threads**: 4 daemon threads (monitor, collect, aggregate, distribute)

---

## 10. Security Considerations

- Federated learning: Only gradients transmitted (no raw data)
- Client authentication: API key required for heartbeats
- Encrypted gradients: Ready for differential privacy integration
- Model hash verification: Clients verify model integrity
- Client isolation: Each organization's data stays local

---

**Implementation Status**: ✅ Complete

All three requirements implemented:
1. ✅ Mitigation techniques added to zero-day alerts
2. ✅ Federated clients real-time implementation
3. ✅ Architecture diagram fully integrated
