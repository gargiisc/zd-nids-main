# AI-NIDS: Comprehensive Implementation Technical Report

**Document Type:** Technical Implementation Report  
**Project:** AI-NIDS (Network Intrusion Detection System)  
**Version:** 1.0  
**Date:** January 28, 2026  
**Repository:** gargi1606/zd-nids

---

## Executive Summary

The AI-NIDS system is a commercial-grade Network Intrusion Detection System that combines signature-based detection, machine learning, behavioral baselines, and federated learning to provide comprehensive threat detection across distributed organizations. This report details the complete implementation architecture, providing insights into how each component integrates to deliver zero-day attack detection capabilities while maintaining privacy through federated learning.

---

## Table of Contents

1. [Implementation Details](#1-implementation-details)
   - 1.a User Interface and Monitoring Dashboard
   - 1.b Network Traffic Collection and Preprocessing
   - 1.c Zero-Day Detection Pipeline
   - 1.d Federated Learning Integration
   - 1.e Control Flow of the Detection System
   - 1.f Logging and System Management
   - 1.g Model Training and Inference Pipeline
   - 1.h Alert Management and Response Coordination

2. [Architectural Diagrams](#2-architectural-diagrams)

3. [Data Flow Analysis](#3-data-flow-analysis)

4. [Technical Considerations](#4-technical-considerations)

---

## 1. Implementation Details

### 1.a. User Interface and Monitoring Dashboard

#### **Architecture Overview**

The dashboard serves as the central control and monitoring interface for the AI-NIDS system, built using Flask web framework with real-time data visualization.

```
┌─────────────────────────────────────────────────────────────┐
│                    FLASK APPLICATION LAYER                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Dashboard   │  │  API Routes  │  │   Auth      │     │
│  │  (dashboard. │  │  (api.py,    │  │  (auth.py)  │     │
│  │   py)        │  │   alerts.py) │  │             │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘     │
│         │                 │                 │             │
│         └─────────────────┼─────────────────┘             │
│                           │                              │
│                    ┌──────▼─────────┐                    │
│                    │   DB Layer     │                    │
│                    │  (SQLAlchemy)  │                    │
│                    └────────────────┘                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### **Key Components**

**1. Dashboard Routes** (`app/routes/dashboard.py`)

Provides real-time visualization of network security metrics through multiple endpoints:

| Endpoint | Purpose | Refresh Rate |
|----------|---------|--------------|
| `/dashboard` | Main dashboard view | Static load |
| `/dashboard/stats` | Security statistics (AJAX) | 5 seconds |
| `/dashboard/traffic` | Traffic timeline data | 10 seconds |
| `/dashboard/alerts/recent` | Recent threats | 5 seconds |
| `/dashboard/attacks/distribution` | Attack type breakdown | 30 seconds |
| `/dashboard/sync` | Full dashboard sync | Manual |

**2. Dashboard Statistics Function**

```python
def get_dashboard_stats():
    """
    Aggregates security metrics including:
    - Total alerts (24h, 7d, 30d)
    - Attack types distribution
    - Top threatening IPs
    - System status
    - Model accuracy metrics
    """
```

**Data Aggregation Strategy:**
- Timestamps indexed in database for rapid queries
- Aggregate functions used instead of loading full datasets
- Summary statistics cached for 60-second validity window
- Real-time updates via AJAX without full page reload

**3. User Authentication & Authorization**

```python
class User(UserMixin, db.Model):
    # Roles: admin, analyst, viewer
    # Permissions matrix:
    # - Admin: Full access (create, read, update, delete)
    # - Analyst: Read/update alerts, run queries
    # - Viewer: Read-only access
```

**4. Frontend Components**

The dashboard integrates with:
- **Chart.js**: Real-time threat trends visualization
- **DataTables**: Interactive alert management
- **Bootstrap**: Responsive grid layout
- **Socket.io** (optional): WebSocket for true real-time updates

**Sample Dashboard Metrics:**

```json
{
  "total_alerts": 1250,
  "alerts_24h": 47,
  "critical_threats": 3,
  "systems_monitored": 25,
  "detection_rate": 0.92,
  "false_positive_rate": 0.03,
  "average_detection_latency_ms": 245,
  "model_accuracy": {
    "xgboost": 0.92,
    "lstm": 0.87,
    "autoencoder": 0.85,
    "ensemble": 0.94
  }
}
```

---

### 1.b. Network Traffic Collection and Preprocessing

#### **Collection Architecture**

The system collects network data through three complementary methods:

```
┌──────────────────────────────────────────────────────────┐
│              NETWORK DATA COLLECTION LAYER               │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────┐ │
│  │  Live Capture  │  │  PCAP Parser   │  │ Zeek/    │ │
│  │  (Scapy)       │  │  (PyShark)     │  │ Suricata │ │
│  └────────┬───────┘  └────────┬───────┘  └────┬─────┘ │
│           │                   │               │        │
│           └───────────────────┼───────────────┘        │
│                               │                        │
│                        ┌──────▼─────────┐              │
│                        │  Flow Extractor│              │
│                        │ (pcap_handler) │              │
│                        └────────┬───────┘              │
│                                 │                      │
│                        ┌────────▼────────┐             │
│                        │  Preprocessing  │             │
│                        │  & Normalization│             │
│                        └────────┬────────┘             │
│                                 │                      │
│                        ┌────────▼────────┐             │
│                        │  ML Feature     │             │
│                        │  Engineering    │             │
│                        └────────┬────────┘             │
│                                 │                      │
│                        ┌────────▼────────┐             │
│                        │  Detection Input│             │
│                        │  (80+ features) │             │
│                        └─────────────────┘             │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

#### **1. Live Packet Capture** (`collectors/live_capture.py`)

**Mechanism:** Uses Scapy library for real-time network sniffing

```python
class LiveCapture:
    """
    Real-time packet capture using Scapy with callback-based 
    packet processing and asynchronous capture threads.
    """
    
    def __init__(self):
        self._capture_thread: Optional[threading.Thread] = None
        self._callbacks: List[PacketCallback] = []
        self._is_capturing = False
```

**Callback Architecture:**

Multiple independent callbacks process captured packets:

| Callback Type | Purpose | Use Case |
|---------------|---------|----------|
| `PrintCallback` | Display packet info | Development/debugging |
| `StatisticsCallback` | Aggregate traffic stats | Dashboard metrics |
| `QueueCallback` | Queue packets for processing | Batch analysis |
| `DetectionCallback` | Real-time threat detection | Production monitoring |

**Extracted Packet Information:**

```python
@dataclass
class CapturedPacket:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str           # TCP, UDP, ICMP, etc.
    length: int
    flags: Dict[str, bool]  # SYN, ACK, FIN, RST, PSH, URG
    payload: bytes
    raw: bytes
    interface: str
```

**Flow Extraction:**

Bidirectional flows are identified using a canonical flow key:

```python
@dataclass
class FlowKey:
    """Unique identifier for bidirectional flow"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    # Canonical form ensures same flow from both directions
    def canonical(self) -> tuple:
        """Return canonicalized form for bidirectional matching"""
        if (self.src_ip, self.src_port) < (self.dst_ip, self.dst_port):
            return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        else:
            return (self.dst_ip, self.dst_port, self.src_ip, self.src_port)
```

#### **2. PCAP File Processing** (`collectors/pcap_handler.py`)

**Dual Backend Support:**

The PCAP handler supports multiple parsing engines for compatibility:

| Backend | Advantages | Disadvantages |
|---------|-----------|---------------|
| PyShark | Full packet details, slow | Requires Wireshark/TShark |
| Scapy | Fast, pure Python | Limited protocol support |
| Native | Lightweight fallback | Basic parsing only |

```python
class PCAPHandler:
    def __init__(self, backend: str = 'auto'):
        """
        Auto-selects best available backend:
        1. Try PyShark (most complete)
        2. Fall back to Scapy (fast)
        3. Fall back to native (minimal)
        """
```

#### **3. IDS Log Integration**

**Suricata Parser** (`collectors/suricata_parser.py`):
- Parses JSON/CSV alert logs from Suricata IDS
- Extracts signature-based detection results
- Maps alerts to network flows

**Zeek Parser** (`collectors/zeek_parser.py`):
- Processes Zeek connection logs
- Extracts network metadata (protocols, durations, byte counts)
- Identifies suspicious behaviors

#### **Data Preprocessing Pipeline** (`ml/preprocessing/preprocessor.py`)

**Stage 1: Data Loading**

```python
class DataPreprocessor:
    def load_dataset(self, file_path: str, dataset_type: str = 'cicids'):
        """
        Load CSV dataset with automatic encoding detection:
        - UTF-8, Latin-1, ISO-8859-1
        - Strip column names automatically
        - Handle low_memory warnings
        """
```

**Stage 2: Data Cleaning**

```python
def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleaning operations:
    1. Remove infinite and NaN values
    2. Remove duplicates
    3. Filter out rows with missing features
    4. Remove outliers (>5 std from mean)
    5. Correct data types
    """
```

**Stage 3: Feature Engineering**

**80+ Network Features Extracted:**

| Feature Category | Examples | Count |
|-----------------|----------|-------|
| Flow Duration | Duration, bytes/second, packets/second | 3 |
| Packet Stats | Total packets (fwd/bwd), lengths (max/min/mean) | 16 |
| Flags | SYN, ACK, FIN, RST, PSH, URG, CWE, ECE counts | 8 |
| Inter-Arrival Time (IAT) | Mean, std, max, min (per direction) | 8 |
| Window Sizes | Initial window bytes (forward/backward) | 2 |
| Bulk Features | Bytes/bulk, packets/bulk, bulk rate | 6 |
| Subflow Stats | Subflow packet/byte counts | 4 |
| Statistical | Down/up ratio, active/idle times | 8 |
| Destination Host | Host count, srv count, error rates | 11 |
| TCP/UDP Specific | Protocol-specific metrics | 6 |

**Stage 4: Normalization & Scaling**

```python
def fit_transform(self, X: pd.DataFrame) -> np.ndarray:
    """
    Normalization strategy:
    1. StandardScaler: (x - mean) / std
    2. Handles NaN/inf by replacing with median
    3. Clipping extreme values (±3 std)
    4. Saves scaler for inference-time transformation
    """
```

**Stage 5: Train/Validation/Test Split**

```
Total Dataset (CICIDS2017 or UNSW-NB15)
         │
         ├─────── 70% ──────── Training Set
         │           │
         │           ├─── 90% ──── Model Training
         │           └─── 10% ──── Validation (hyperparameter tuning)
         │
         ├─────── 30% ──────── Test Set
         │           (Never seen during training)
         │
         └─────── 15% ──────── Hold-out Test Set (optional)
```

---

### 1.c. Zero-Day Detection Pipeline

#### **Multi-Layer Anomaly Detection**

Zero-day attacks (previously unknown threats) are detected through an ensemble of anomaly detectors working in parallel:

```
┌──────────────────────────────────────────────────────────────┐
│         ZERO-DAY DETECTION PIPELINE                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Network Flow                                                │
│      │                                                        │
│      ├─► Reconstruction Error ────────┐                      │
│      │   Detector (Autoencoder)       │                      │
│      │                                 │                      │
│      ├─► Isolation Forest ────────────┤                      │
│      │   Anomaly Scorer               │                      │
│      │                                 │                      │
│      ├─► Statistical Detector ────────┼──► Ensemble ─────────┤
│      │   (Z-Score, MAD)               │    Aggregation   │
│      │                                 │    (Voting)      │
│      ├─► Baseline Deviation ──────────┤                     │
│      │   Comparison                   │                     │
│      │                                 │                     │
│      ├─► Temporal Spike Detection ────┤                     │
│      │                                 │                      │
│      └─► Entropy Anomaly Detector ────┘                      │
│                                                              │
│      Anomaly Score: 0.0 - 1.0                               │
│      Confidence: 0.0 - 1.0                                  │
│                                                              │
│      If Score > Threshold: FLAG AS ZERO-DAY                 │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

#### **Detector 1: Reconstruction Error (Autoencoder)**

```python
class ReconstructionErrorDetector:
    """
    Detects anomalies based on how well the autoencoder
    can reconstruct the input. Normal patterns reconstruct
    well; anomalies have high reconstruction error.
    """
    
    def predict(self, features: np.ndarray) -> Tuple[float, str]:
        # Normal traffic reconstruction error: ~0.1
        # Anomalous traffic reconstruction error: ~0.85+
        
        reconstruction_error = ||actual - reconstructed||₂
        
        if error > threshold_95th_percentile:
            return (high_score, "Reconstruction Error")
```

**Why This Works:**
- Autoencoder trained only on normal traffic
- Novel attack patterns don't match learned normal patterns
- Reconstruction error indicates "out-of-distribution" behavior

#### **Detector 2: Isolation Forest**

```python
class IsolationForestDetector:
    """
    Statistical anomaly detection using Isolation Forest.
    Isolates anomalies by randomly selecting features and splits.
    Anomalies are easier to isolate than normal points.
    """
    
    def predict(self, features: np.ndarray) -> float:
        # Anomaly score: number of splits needed to isolate
        # Normal: many splits (depth in tree)
        # Anomalous: few splits (easily isolated)
```

#### **Detector 3: Statistical Deviation**

```python
class StatisticalDetector:
    """
    Detects anomalies using statistical measures:
    - Z-Score: (x - mean) / std
    - MAD (Median Absolute Deviation): robust to outliers
    """
    
    z_score = (value - baseline_mean) / baseline_std
    
    if abs(z_score) > 3.0:
        return (high_score, f"Statistical Deviation ({z_score:.2f} std)")
```

**Baseline Calculation:**
Computed from historical normal traffic:
```
Mean = Σ(normal_values) / count
Std = sqrt(Σ(value - mean)²) / (count - 1)
```

#### **Detector 4: Behavioral Baseline Deviation**

```python
class BaselineDeviationDetector:
    """
    Compares current flow against per-host/subnet baselines.
    Example: "192.168.1.24 normally has 10 DNS queries/min,
    now has 500" → ANOMALY
    """
    
    baseline = historical_stats[host_ip]
    
    if current_traffic > baseline.mean + (3 * baseline.std):
        return (high_score, "Baseline Deviation")
```

**Baseline Dimensions:**
- Per-host: Port usage, protocol ratios, traffic volume
- Per-subnet: Aggregate bandwidth, connection patterns
- Per-protocol: TCP window sizes, flag patterns, IAT stats
- Time-of-day: Traffic patterns vary by hour (business hours)

#### **Detector 5: Temporal Spike Detection**

```python
class TemporalSpikeDetector:
    """
    Detects sudden changes in traffic patterns.
    Maintains sliding windows of traffic statistics.
    """
    
    current_rate = packets_in_last_60s
    historical_rate = mean(packets_per_minute_last_7days)
    
    if current_rate > historical_rate * 10:
        return (high_score, "Traffic Spike (10x increase)")
```

#### **Detector 6: Entropy Anomaly**

```python
class EntropyDetector:
    """
    Measures entropy (randomness) in traffic patterns.
    Normal: High entropy (diverse destinations)
    Scan: Low entropy (repeated patterns)
    """
    
    destination_entropy = entropy(destination_port_distribution)
    
    if destination_entropy < threshold:
        return (high_score, "Low entropy (possible port scan)")
```

#### **Ensemble Aggregation Strategy**

```python
@dataclass
class ZeroDayDetectionResult:
    is_anomaly: bool           # Final decision
    anomaly_score: float       # Ensemble score (0-1)
    confidence: float          # How confident in decision
    detector_scores: Dict      # Individual detector scores
    primary_detectors: List    # Which detectors triggered
    reasoning: str             # Explainability
```

**Aggregation Logic:**

```python
def aggregate_detector_results(detector_results):
    """
    Combines multiple detector results:
    
    1. Weighted Average: 
       score = 0.3 * reconstruction + 0.25 * isolation + 
               0.2 * statistical + 0.15 * baseline + 0.1 * entropy
    
    2. Voting Threshold:
       anomaly_score = (# detectors triggered) / (# total detectors)
    
    3. Confidence = agreement among detectors
    """
    
    detector_count = len([d for d in results if d.is_anomalous])
    total_detectors = len(results)
    confidence = detector_count / total_detectors
    
    return ZeroDayDetectionResult(
        is_anomaly=anomaly_score > 0.5,
        anomaly_score=weighted_average,
        confidence=confidence
    )
```

#### **Attack Classification**

Once zero-day flag is raised, the system attempts classification:

```python
def classify_anomaly_type(results: List[AnomalyDetectionResult]) -> str:
    """
    Hints for attack classification:
    - High entropy + low traffic: Port scan
    - Low entropy + high traffic: DDoS/Flood
    - Reconstruction error only: Novel encoding
    - Baseline deviation only: Policy violation
    """
    
    if low_entropy and high_traffic:
        return "Potential DDoS"
    elif high_entropy and low_traffic:
        return "Potential Reconnaissance"
    elif reconstruction_error > 0.8:
        return "Novel Pattern"
    else:
        return "Unknown Anomaly"
```

---

### 1.d. Federated Learning Integration

#### **Federated Learning Architecture**

Federated learning enables privacy-preserving collaborative model improvement:

```
┌────────────────────────────────────────────────────────────────┐
│         FEDERATED LEARNING COORDINATION FLOW                   │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Round N:                                                      │
│  ┌──────────────────────────────────────────────────────┐     │
│  │  1. Global Model Broadcast                          │     │
│  │     (Version N to all clients)                       │     │
│  │                                                      │     │
│  │  2. Local Training (Parallel)                        │     │
│  │     [Bank] [Hospital] [Telecom] [Retail]            │     │
│  │      ...trains locally with own data...             │     │
│  │                                                      │     │
│  │  3. Gradient Extraction                             │     │
│  │     Client computes: weight_delta = model - prev    │     │
│  │                                                      │     │
│  │  4. Secure Transmission                             │     │
│  │     Encrypt gradient with differential privacy      │     │
│  │     NO raw data transmitted                         │     │
│  │                                                      │     │
│  │  5. Server Aggregation (FedAvg)                     │     │
│  │     New_Global = Σ(weight_sample * client_delta)   │     │
│  │     Byzantine detection: exclude outliers           │     │
│  │     Differential privacy noise added               │     │
│  │                                                      │     │
│  │  6. Model Distribution                              │     │
│  │     Broadcast aggregated model (Version N+1)        │     │
│  │                                                      │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                                │
│  Repeat with Round N+1...                                     │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

#### **Component 1: Federated Server** (`federated/federated_server.py`)

**Responsibilities:**
1. Manage federated learning rounds
2. Aggregate client updates
3. Maintain global model state
4. Broadcast updated models
5. Track client participation

```python
class FederatedServer:
    """
    Central server coordinating federated learning.
    Maintains global model and aggregates client updates.
    """
    
    def __init__(self, model_template: Dict[str, torch.Tensor]):
        self.global_model_state = model_template
        self.current_round = 0
        self.round_history = []
        self.clients = {}
        self.round_updates = []
```

**Round Orchestration:**

```python
def start_round(self) -> int:
    """Initiate a new federated learning round"""
    self.current_round += 1
    logger.info(f"Starting round {self.current_round}")
    return self.current_round

def submit_update(self, client_id: str, gradients: Dict, metrics: Dict) -> bool:
    """Accept gradient update from client"""
    # Validate update quality
    # Store in round buffer
    # Check if sufficient clients have submitted

def aggregate_round(self) -> RoundInfo:
    """Combine all client updates into new global model"""
    # Extract metrics and gradients
    # Call aggregator with selected strategy
    # Detect Byzantine clients
    # Apply differential privacy
    # Store new global model
```

**Aggregation Strategies:**

| Strategy | Formula | Use Case |
|----------|---------|----------|
| **FedAvg** | New = Old + Σ(weight × delta) | Baseline, IID data |
| **FedProx** | Add proximal term μ\|\|w-w_prev\|\|² | Non-IID (heterogeneous) data |
| **FedOpt** | Server-side optimizer + momentum | Faster convergence |
| **Weighted** | Weight by sample count | Respect client dataset sizes |

#### **Component 2: Federated Clients** (`federated/federated_client.py`)

**Client Responsibilities:**

```python
class FederatedClient:
    """
    Local detector client participating in federated learning.
    Trains locally, computes gradients, sends to server.
    """
    
    def participate_in_round(self, global_weights):
        """
        1. Load global model weights
        2. Train on local data
        3. Compute gradients
        4. Collect training metrics
        5. Return to server
        """
```

**Local Training Flow:**

```python
def train_local(self, X_local, y_local):
    """
    Local training on client's data:
    
    1. Load global model: model.load_state_dict(global_weights)
    2. Train: model.fit(X_local, y_local, epochs=5)
    3. Compute delta: new_weights - old_weights
    4. Calculate metrics: accuracy, loss, samples
    5. Return: (gradients, metrics)
    """
    
    old_weights = copy(self.model.state_dict())
    self.model.fit(X_local, y_local)
    new_weights = self.model.state_dict()
    
    gradients = {
        name: new_weights[name] - old_weights[name]
        for name in new_weights.keys()
    }
    
    return (gradients, training_metrics)
```

**Data Privacy:**
- Raw data NEVER leaves client
- Only gradients (model weight changes) transmitted
- Gradients encrypted using differential privacy
- Gradient magnitude clipping prevents information leakage

#### **Component 3: Secure Aggregation** (`federated/secure_aggregator.py`)

**Privacy Mechanisms:**

```python
class SecureAggregator:
    """
    Implements privacy-preserving aggregation protocols.
    
    Guarantees:
    - Server cannot see individual client updates
    - Byzantine clients detected and excluded
    - Differential privacy bounds privacy loss
    """
```

**Masking Protocol:**

```
Step 1: Setup
  For each pair of clients (i, j):
    Generate shared random seed
    
Step 2: Mask Generation (Client-side)
  Client i computes mask_i from seed with all neighbors
  mask_i = SHA256(seed_i1 || seed_i2 || ... || seed_in)
  
Step 3: Masked Submission (Client-side)
  Client i sends: gradient_i + mask_i
  
Step 4: Aggregation (Server-side)
  Aggregate = Σ(gradient_i + mask_i)
  
Step 5: Unmask (Server-side)
  Since Σ(mask_i) = 0 (symmetric), masks cancel:
  Final = Aggregate (masks disappeared)
  
Result: Server sees sum WITHOUT seeing individual updates!
```

**Differential Privacy:**

```python
def add_differential_privacy_noise(gradients, epsilon=1.0):
    """
    Adds Laplace or Gaussian noise to protect individual privacy.
    
    Parameter ε (epsilon):
    - ε < 1.0: Strong privacy (more noise)
    - ε = 1.0: Balanced (used here)
    - ε > 1.0: Weak privacy (less noise)
    
    Privacy interpretation:
    "With ε=1.0, an attacker has at most e^1.0 ≈ 2.7x more
    confidence in any conclusion about an individual's data"
    """
    
    for param_name, param in gradients.items():
        noise = np.random.laplace(0, sensitivity / epsilon, param.shape)
        gradients[param_name] += noise
    
    return gradients
```

**Byzantine Detection:**

```python
def detect_byzantine_clients(updates: List[Dict]) -> List[str]:
    """
    Identifies malicious clients attempting to corrupt global model.
    
    Detection method: Krum's algorithm
    - Compute distance between each pair of updates
    - Client with maximum average distance to others = suspicious
    - Exclude top K% most different clients
    """
    
    for each_client:
        distances = [L2_distance(client_update, other_updates)
                     for other in all_clients]
        avg_distance = mean(distances)
    
    suspicious = clients_with_top_5_percent_distances
    return suspicious
```

#### **Component 4: Real-Time Coordinator** (`detection/federated_learning_flow.py`)

Coordinates continuous federated learning with detection pipeline:

```python
class RealTimeFederatedLearningCoordinator:
    """
    Orchestrates real-time federated learning:
    1. Collects local detections
    2. Aggregates updates
    3. Distributes global model
    4. Tracks new attack types
    """
    
    def _round_orchestrator(self):
        """Background thread managing federated rounds"""
        while self.running:
            # Wait for round timer
            # Collect updates from available clients
            # Perform aggregation
            # Distribute results
            # Log round statistics
```

**New Attack Discovery:**

```python
def extract_new_attacks(training_metrics: Dict) -> List[str]:
    """
    Identifies attack types newly detected in this round.
    
    Used to answer:
    "Which new threats did we collectively discover?"
    
    Aggregates across all organizations:
    """
    
    new_attacks = set()
    for client_metrics in all_metrics:
        for attack_type in client_metrics.get('new_attacks', []):
            # Only count if detected by >1 organization
            if attack_type not in global_attack_registry:
                new_attacks.add(attack_type)
    
    return list(new_attacks)
```

---

### 1.e. Control Flow of the Detection System

#### **High-Level System Control Flow**

```
┌─────────────────────────────────────────────────────────────┐
│              DETECTION SYSTEM INITIALIZATION                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Application Startup (run.py)                            │
│     ├─ Create Flask app                                     │
│     ├─ Initialize database                                  │
│     ├─ Load ML models (XGBoost, Autoencoder, LSTM)         │
│     ├─ Initialize detection engine                          │
│     ├─ Start background threads:                            │
│     │  ├─ Live packet capture                              │
│     │  ├─ Federated learning coordinator                   │
│     │  ├─ Baseline profiler                                │
│     │  └─ Alert aggregator                                 │
│     └─ Start Flask web server                              │
│                                                             │
│  2. Real-Time Detection Loop                               │
│     ├─ Receive network flow                                │
│     ├─ Extract 80+ features                                │
│     ├─ Preprocess (normalize, scale)                       │
│     ├─ Run ML ensemble                                     │
│     ├─ Run zero-day detectors                              │
│     ├─ Check behavioral baselines                          │
│     ├─ Generate alert (if threatening)                     │
│     ├─ Execute response (if configured)                    │
│     └─ Store in database                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### **Per-Flow Detection Process**

```
Input: Network Flow (src_ip, dst_ip, src_port, dst_port, ...)
│
├─► Stage 1: Feature Extraction
│   ├─ Raw features from packet capture
│   ├─ Flow-level aggregation
│   └─ 80+ engineered features
│
├─► Stage 2: Preprocessing
│   ├─ Normalization (StandardScaler)
│   ├─ Scaling to [0, 1]
│   ├─ NaN handling
│   └─ Outlier clipping
│
├─► Stage 3: Parallel Detection
│   ├─► ML Ensemble Detection
│   │   ├─ XGBoost: Attack classification
│   │   ├─ LSTM: Sequence pattern matching
│   │   └─ Weighted voting
│   │   Result: (attack_type, confidence)
│   │
│   ├─► Zero-Day Detection
│   │   ├─ Autoencoder reconstruction error
│   │   ├─ Isolation Forest scoring
│   │   ├─ Statistical deviation
│   │   ├─ Baseline deviation
│   │   ├─ Temporal spike detection
│   │   └─ Entropy analysis
│   │   Result: (anomaly_score, confidence)
│   │
│   └─► Behavioral Baseline Check
│       ├─ Per-host baseline comparison
│       ├─ Per-subnet aggregate stats
│       ├─ Per-protocol patterns
│       └─ Time-of-day analysis
│       Result: (deviation_score, baseline_comparison)
│
├─► Stage 4: Result Aggregation
│   ├─ Combine detector scores
│   ├─ Calculate ensemble confidence
│   ├─ Determine severity level
│   └─ Generate final decision
│   Result: DetectionResult
│
├─► Stage 5: SHAP Explainability
│   ├─ Feature importance analysis
│   ├─ Local explanation generation
│   └─ Create reasoning text
│   Result: explanation dictionary
│
├─► Stage 6: Alert Generation (if attack detected)
│   ├─ Create Alert record
│   ├─ Store in database
│   ├─ Update dashboards
│   └─ Trigger notifications
│   Result: Alert stored and visible
│
└─► Stage 7: Response (if enabled)
    ├─ Check response policy
    ├─ Execute response actions:
    │  ├─ Block IP (firewall rule)
    │  ├─ Quarantine host
    │  ├─ Rate limit
    │  ├─ Capture traffic
    │  └─ Notify SOC
    └─ Log response execution
    Result: Threat mitigated/contained

Output: Alert in database, potentially actions taken
```

#### **Detection Engine Code Flow** (`detection/detector.py`)

```python
class DetectionEngine:
    def detect(self, features, metadata=None) -> Union[DetectionResult, List[DetectionResult]]:
        """
        Main detection entry point.
        
        Flow:
        1. Prepare input (validate, convert format)
        2. Run appropriate detector:
           - Single flow: _detect_single()
           - Batch flows: _detect_batch()
        3. Aggregate results
        4. Generate explanations
        5. Return DetectionResult(s)
        """
        
        X, metadata = self._prepare_input(features)
        
        if len(X) == 1:
            return self._detect_single(X[0], metadata[0])
        else:
            return self._detect_batch(X, metadata)
    
    def _detect_single(self, features, metadata):
        """Single flow detection"""
        
        # Preprocess
        features_normalized = self.preprocessor.transform(features)
        
        # ML Models
        xgb_pred = self.xgboost_model.predict(features_normalized)
        lstm_pred = self.lstm_model.predict(features_normalized)
        ensemble_pred = self.ensemble_model.predict(features_normalized)
        
        # Zero-day
        zero_day_result = self.zero_day_detector.detect(features_normalized)
        
        # Baselines
        baseline_deviation = self.baseline_engine.check(metadata)
        
        # Aggregate
        is_attack = ensemble_pred['probability'] > 0.5 or zero_day_result.is_anomaly
        
        # Explainability
        shap_explanation = self.explainer.explain(features_normalized)
        
        return DetectionResult(
            is_attack=is_attack,
            attack_type=ensemble_pred['class'],
            confidence=ensemble_pred['probability'],
            severity=self._calculate_severity(ensemble_pred['probability']),
            model_used='ensemble',
            shap_explanation=shap_explanation
        )
```

---

### 1.f. Logging and System Management

#### **Logging Architecture**

```
┌───────────────────────────────────────────────────────────┐
│                LOGGING SYSTEM                             │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Application Logger (app/__init__.py)                 │ │
│  │ ├─ Level: configurable (INFO, DEBUG, ERROR)         │ │
│  │ ├─ Format: timestamp, logger, level, message        │ │
│  │ ├─ Output: console + file (data/logs/nids.log)     │ │
│  │ └─ Rotation: daily (configurable)                  │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                           │
│  Loggers by component:                                   │
│  ├─ app                → Application/Flask logs          │
│  ├─ app.routes         → API request/response            │
│  ├─ detection          → Detection pipeline events       │
│  ├─ ml                 → Model training/inference        │
│  ├─ federated          → Federated learning rounds       │
│  ├─ response           → Response action execution       │
│  ├─ collectors         → Traffic capture events          │
│  └─ behavior           → Baseline updates                │
│                                                           │
│  Severity Levels:                                         │
│  ├─ DEBUG   → Detailed diagnostic info (verbose)         │
│  ├─ INFO    → General system status (default)            │
│  ├─ WARNING → Warning conditions (unexpected)            │
│  ├─ ERROR   → Error conditions (must fix)                │
│  └─ CRITICAL→ Critical errors (system failure)           │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

#### **Log Configuration** (`app/__init__.py`)

```python
def setup_logging(app):
    """Configure application-wide logging"""
    
    # Root logger
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))
    logging.basicConfig(level=log_level)
    
    # File handler (persistent storage)
    if app.config.get('LOG_FILE'):
        file_handler = RotatingFileHandler(
            app.config['LOG_FILE'],
            maxBytes=10485760,  # 10 MB
            backupCount=10      # Keep 10 rotated files
        )
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)
```

#### **Key Log Events**

| Event | Component | Level | Example |
|-------|-----------|-------|---------|
| Model Load | Detection | INFO | "Loaded XGBoost model from /path/to/model" |
| New Alert | Detection | WARNING | "CRITICAL alert: DDoS from 192.168.1.50 (confidence 0.95)" |
| FL Round | Federated | INFO | "Federated round 42: 5 clients, accuracy 0.94" |
| Response Action | Response | INFO | "Blocked IP 192.168.1.50 for 24 hours" |
| Error | Any | ERROR | "Failed to connect to database: connection timeout" |
| API Request | Routes | DEBUG | "GET /api/v1/alerts with params {limit: 10}" |

#### **Database Audit Trail**

Alerts table includes comprehensive tracking:

```python
class Alert(db.Model):
    # Detection metadata
    timestamp = db.Column(db.DateTime, index=True)
    attack_type = db.Column(db.String(100), index=True)
    severity = db.Column(db.String(20), index=True)
    confidence = db.Column(db.Float)
    
    # User interactions
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    acknowledged_at = db.Column(db.DateTime)
    
    resolved = db.Column(db.Boolean, default=False)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    resolved_at = db.Column(db.DateTime)
    resolution_notes = db.Column(db.Text)
    
    # Response execution
    mitigation_applied = db.Column(db.Boolean, default=False)
    mitigation_timestamp = db.Column(db.DateTime)
    
    # Federated learning context
    fed_learning_round = db.Column(db.Integer)
    fed_client_id = db.Column(db.String(100))
```

#### **System Metrics Tracking**

```python
class SystemMetrics(db.Model):
    """Track system performance metrics"""
    
    timestamp = db.Column(db.DateTime, index=True)
    
    # Detection metrics
    alerts_detected = db.Column(db.Integer)
    false_positives = db.Column(db.Integer)
    detection_latency_ms = db.Column(db.Float)
    
    # Model metrics
    model_accuracy = db.Column(db.Float)
    model_precision = db.Column(db.Float)
    model_recall = db.Column(db.Float)
    
    # System health
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    disk_usage = db.Column(db.Float)
    active_connections = db.Column(db.Integer)
```

---

### 1.g. Model Training and Inference Pipeline

#### **Training Pipeline** (`ml/training/trainer.py`)

```
┌───────────────────────────────────────────────────────────────┐
│                    TRAINING PIPELINE                          │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  Step 1: Data Loading & Preprocessing                        │
│  ├─ Load CICIDS2017 or UNSW-NB15 dataset                     │
│  ├─ Clean: remove NaN, infinite, duplicates                 │
│  ├─ Feature selection: 80 most important features           │
│  ├─ Normalization: StandardScaler fit on training data      │
│  └─ Split: 70% train, 15% validation, 15% test            │
│                                                               │
│  Step 2: Individual Model Training (Parallel)                │
│  │                                                            │
│  ├─► XGBoost Training                                        │
│  │   ├─ n_estimators=100, max_depth=6                       │
│  │   ├─ Training: supervised (labels required)              │
│  │   ├─ Optimization: gradient boosting                     │
│  │   └─ Output: attack_type classification                  │
│  │   Result: ~92% accuracy on test set                      │
│  │                                                            │
│  ├─► Autoencoder Training                                    │
│  │   ├─ Training data: ONLY normal traffic (benign)        │
│  │   ├─ Architecture: [80 → 32 → 16 → 32 → 80]            │
│  │   ├─ Loss: MSE (reconstruction error)                    │
│  │   ├─ Optimization: Adam optimizer                        │
│  │   ├─ Epochs: 100, early stopping enabled                │
│  │   └─ Output: latent representation + reconstruction      │
│  │   Result: Learns normal traffic patterns                 │
│  │                                                            │
│  └─► LSTM Training                                           │
│      ├─ Sequence length: 10 packets per sequence            │
│      ├─ Architecture: 2 LSTM layers (64 units each)        │
│      ├─ Bidirectional: captures both directions            │
│      ├─ Dropout: 0.3 (regularization)                      │
│      ├─ Training: supervised with labels                    │
│      └─ Output: attack sequence classification              │
│      Result: ~87% accuracy on temporal patterns             │
│                                                               │
│  Step 3: Model Evaluation                                    │
│  ├─ Metrics: accuracy, precision, recall, F1-score, AUC    │
│  ├─ Confusion matrix: see misclassifications               │
│  ├─ ROC curve: evaluate at different thresholds            │
│  └─ Per-class performance: all attack types                │
│                                                               │
│  Step 4: Ensemble Creation                                  │
│  ├─ Load trained individual models                          │
│  ├─ Set weights: XGBoost=0.4, Autoencoder=0.3, LSTM=0.3   │
│  ├─ Strategy: weighted average of probabilities            │
│  └─ Save ensemble configuration                             │
│                                                               │
│  Step 5: Model Saving                                       │
│  ├─ XGBoost: JSON format + pickle                          │
│  ├─ Autoencoder: PyTorch state_dict                        │
│  ├─ LSTM: PyTorch state_dict                               │
│  ├─ Preprocessor: pickle (scaler, encoder)                 │
│  └─ Location: data/saved_models/                            │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

#### **Model Specifications**

**XGBoost Classifier:**

```python
model = XGBClassifier(
    n_estimators=100,      # Number of trees
    max_depth=6,           # Tree depth limit
    learning_rate=0.1,     # Shrinkage parameter
    subsample=0.8,         # Row subsampling
    colsample_bytree=0.8,  # Feature subsampling
    n_jobs=-1              # Use all CPU cores
)

# Training
model.fit(X_train, y_train, eval_set=[(X_val, y_val)])
```

**Autoencoder (PyTorch):**

```python
class AutoencoderNetwork(nn.Module):
    def __init__(self, input_dim=80):
        super().__init__()
        
        # Encoder: 80 → 64 → 32 → 16
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16)
        )
        
        # Decoder: 16 → 32 → 64 → 80
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim)
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
```

**LSTM Detector:**

```python
class LSTMNetwork(nn.Module):
    def __init__(self, input_dim=80, hidden_dim=64, num_classes=2):
        super().__init__()
        
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=2,
            bidirectional=True,
            dropout=0.3,
            batch_first=True
        )
        
        self.fc = nn.Linear(hidden_dim * 2, num_classes)
    
    def forward(self, sequences):
        # sequences shape: (batch, seq_len, input_dim)
        lstm_out, _ = self.lstm(sequences)
        # Use last output: (batch, 2*hidden_dim)
        logits = self.fc(lstm_out[:, -1, :])
        return logits
```

#### **Inference Pipeline**

```
Input Network Flow
│
├─► 1. Feature Extraction (pcap_handler or live_capture)
│   └─ 80 engineered features
│
├─► 2. Preprocessing
│   ├─ Load preprocessor from disk
│   ├─ Apply normalization
│   └─ Scale features
│
├─► 3. Model Inference (Parallel)
│   │
│   ├─► XGBoost.predict()
│   │   └─ Output: (attack_class, probability)
│   │
│   ├─► Autoencoder.forward()
│   │   ├─ Input through encoder → latent
│   │   ├─ Latent through decoder → reconstructed
│   │   └─ Output: reconstruction_error = MSE(input, reconstructed)
│   │
│   └─► LSTM.forward()
│       ├─ Input: sequence of 10 packets
│       └─ Output: (attack_class, probability)
│
├─► 4. Ensemble Aggregation
│   ├─ XGBoost score: 40%
│   ├─ LSTM score: 30%
│   ├─ Autoencoder anomaly: 30%
│   └─ Final decision: weighted average
│
├─► 5. Confidence Calculation
│   ├─ Agreement among models
│   ├─ Probability thresholds
│   └─ Confidence score (0-1)
│
└─► Output: DetectionResult
    ├─ attack_type: "DDoS"
    ├─ confidence: 0.94
    ├─ severity: "CRITICAL"
    └─ shap_explanation: {...}

Alert Generated if confidence > threshold
```

#### **Explainability with SHAP** (`ml/explainability/shap_explainer.py`)

```python
class SHAPExplainer:
    """
    SHAP (SHapley Additive exPlanations) for model interpretability.
    Shows which features contributed most to detection decision.
    """
    
    def explain(self, features, model):
        """
        Generate explanation for prediction.
        
        Output: Feature importance scores showing
        - Which features pushed model toward "attack"
        - Which features pushed toward "benign"
        - Magnitude of each feature's contribution
        """
        
        explainer = shap.TreeExplainer(model)  # for XGBoost
        shap_values = explainer.shap_values(features)
        
        return {
            'top_attacking_features': [
                {'feature': name, 'value': value, 'shap': shap}
                for name, value, shap in top_k(shap_values)
            ],
            'prediction': model.predict(features),
            'base_value': explainer.expected_value
        }
```

---

### 1.h. Alert Management and Response Coordination

#### **Alert Lifecycle**

```
DETECTION EVENT
│
├─► 1. Alert Creation (detection/detector.py)
│   ├─ Detected attack → DetectionResult
│   ├─ Generate Alert record
│   ├─ Compute SHAP explanation
│   └─ Store in database
│
├─► 2. Alert Storage & Indexing
│   ├─ Store in SQLite/PostgreSQL
│   ├─ Create indices for fast queries:
│   │  ├─ idx_alert_severity_timestamp
│   │  ├─ idx_alert_type_timestamp
│   │  └─ idx_source_destination_ip
│   └─ Trigger dashboard updates
│
├─► 3. User Notification
│   ├─ Web dashboard: real-time update
│   ├─ Email (optional): high-severity alerts
│   ├─ Slack/Teams (optional): webhook integration
│   └─ Bell icon: unacknowledged count
│
├─► 4. User Review
│   ├─ SOC analyst views dashboard
│   ├─ Clicks to see alert details:
│   │  ├─ Network info (IPs, ports)
│   │  ├─ Detection confidence
│   │  ├─ Model explanation (SHAP)
│   │  ├─ Raw flow data
│   │  └─ Response history
│   └─ Marks alert as acknowledged
│
├─► 5. Investigation & Response
│   ├─ Analyst decides on response:
│   │  ├─ False positive → Mark resolved
│   │  ├─ True attack → Execute response
│   │  └─ Investigate → Capture more data
│   └─ Executes response (if auto-response enabled)
│
├─► 6. Response Execution (response/response_engine.py)
│   ├─ Severity-based response mapping:
│   │  ├─ CRITICAL (>0.9): Block IP immediately
│   │  ├─ HIGH (0.7-0.9): Quarantine + alert SOC
│   │  ├─ MEDIUM (0.5-0.7): Rate limit
│   │  ├─ LOW (0.3-0.5): Monitor
│   │  └─ INFO (<0.3): Log only
│   └─ Can be rolled back if false positive detected
│
├─► 7. Response Logging
│   ├─ Store response result in database
│   ├─ Firewall rule creation logged
│   ├─ Traffic capture recorded
│   └─ SOC notifications tracked
│
└─► 8. Alert Resolution
    ├─ Analyst confirms response effectiveness
    ├─ Marks alert as resolved
    ├─ Adds resolution notes
    └─ Audit trail complete (who, what, when)
```

#### **Response Engine** (`response/response_engine.py`)

```python
class ResponseEngine:
    """
    Automated threat response execution.
    Maps detection confidence to proportional response.
    """
    
    DEFAULT_RESPONSE_MAP = {
        (0.9, 1.0): ResponseLevel.BLOCK,        # Immediate block
        (0.7, 0.9): ResponseLevel.QUARANTINE,   # Isolate host
        (0.5, 0.7): ResponseLevel.RATE_LIMIT,   # Throttle
        (0.3, 0.5): ResponseLevel.MONITOR,      # Watch carefully
        (0.0, 0.3): ResponseLevel.LOG_ONLY      # Just log
    }
    
    def execute_response(self, alert: Alert) -> ResponseResult:
        """Execute appropriate response for alert"""
        
        response_level = self.determine_response_level(alert.confidence)
        
        if response_level == ResponseLevel.BLOCK:
            return self._block_ip(alert.source_ip, duration_hours=24)
        elif response_level == ResponseLevel.QUARANTINE:
            return self._quarantine_host(alert.source_ip)
        elif response_level == ResponseLevel.RATE_LIMIT:
            return self._rate_limit(alert.source_ip, alert.source_port)
```

**Response Actions:**

| Action | Effect | Reversible | Used For |
|--------|--------|-----------|----------|
| LOG | Write to log file | ✓ N/A | Low-confidence alerts |
| ALERT | Notify SOC team | ✓ N/A | Medium-confidence |
| WATCHLIST_ADD | Add to watchlist | ✓ Yes | Suspicious sources |
| RATE_LIMIT | Throttle traffic | ✓ Yes | Potential DoS |
| BLOCK_IP | Deny all traffic | ✓ Yes | Confirmed attacker |
| QUARANTINE_HOST | Isolate from network | ✓ Yes | Compromised host |
| CAPTURE_TRAFFIC | Record packets | ✓ Yes | Forensics/investigation |
| CREATE_TICKET | Open incident ticket | ✓ Yes | SOC workflow |

---

## 2. Architectural Diagrams

### **2.1 System Architecture Overview**

```
┌────────────────────────────────────────────────────────────────────┐
│                     AI-NIDS SYSTEM ARCHITECTURE                    │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │              PRESENTATION LAYER                             │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐    │ │
│  │  │  Web         │  │  RESTful     │  │  WebSocket     │    │ │
│  │  │  Dashboard   │  │  API         │  │  (Real-time)   │    │ │
│  │  └──────────────┘  └──────────────┘  └────────────────┘    │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                               ▲                                    │
│                               │ (HTTP/WebSocket)                  │
│  ┌────────────────────────────┴──────────────────────────────────┐ │
│  │              APPLICATION LAYER (Flask)                        │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐     │ │
│  │  │  Auth &      │  │  Alert       │  │  Analytics &   │     │ │
│  │  │  User Mgmt   │  │  Management  │  │  Reporting     │     │ │
│  │  └──────────────┘  └──────────────┘  └────────────────┘     │ │
│  └────────────────────────┬───────────────────────────────────────┘ │
│                           │                                         │
│  ┌────────────────────────┴───────────────────────────────────────┐ │
│  │              DETECTION ENGINE LAYER                           │ │
│  │  ┌──────────────────────────────────────────────────────┐    │ │
│  │  │  Detection Orchestrator (detector.py)               │    │ │
│  │  │  ├─ ML Ensemble (XGBoost + LSTM + Autoencoder)    │    │ │
│  │  │  ├─ Zero-Day Detector (6 anomaly algorithms)       │    │ │
│  │  │  ├─ Baseline Engine (behavioral analysis)          │    │ │
│  │  │  └─ Response Engine (automated response)           │    │ │
│  │  └──────────────────────────────────────────────────────┘    │ │
│  └────────────────────────┬───────────────────────────────────────┘ │
│                           │                                         │
│  ┌────────────────────────┴───────────────────────────────────────┐ │
│  │              DATA COLLECTION LAYER                            │ │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────────────────┐   │ │
│  │  │  Live      │ │  PCAP      │ │  Zeek/Suricata Logs    │   │ │
│  │  │  Capture   │ │  Parser    │ │  (Signature-based IDS) │   │ │
│  │  └────────────┘ └────────────┘ └────────────────────────┘   │ │
│  │        │               │                  │                  │ │
│  │        └───────────────┼──────────────────┘                  │ │
│  │                        │                                      │ │
│  │        ┌───────────────▼─────────────────┐                 │ │
│  │        │  Preprocessor & Feature         │                 │ │
│  │        │  Engineering                    │                 │ │
│  │        │  (80+ network features)         │                 │ │
│  │        └──────────────────────────────────┘                 │ │
│  └────────────────────────┬───────────────────────────────────────┘ │
│                           │                                         │
│  ┌────────────────────────┴───────────────────────────────────────┐ │
│  │              STORAGE LAYER                                    │ │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐   │ │
│  │  │  Alert     │  │  Network   │  │  Model Artifacts &   │   │ │
│  │  │  Database  │  │  Flows DB  │  │  Training History    │   │ │
│  │  │  (SQL)     │  │  (SQL)     │  │  (Files)             │   │ │
│  │  └────────────┘  └────────────┘  └──────────────────────┘   │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │              FEDERATED LEARNING LAYER (Optional)             │ │
│  │  ┌──────────────────────────────────────────────────────┐   │ │
│  │  │  Federated Server (Central Aggregator)              │   │ │
│  │  │  Secure Aggregation + Differential Privacy         │   │ │
│  │  │  Byzantine Detection + Model Aggregation           │   │ │
│  │  └──────────────────────────────────────────────────────┘   │ │
│  │     ▲                ▲                  ▲                    │ │
│  │     │                │                  │                    │ │
│  │  ┌──────┐         ┌──────┐         ┌──────┐                 │ │
│  │  │Client│         │Client│         │Client│                 │ │
│  │  │ 1    │         │ 2    │         │ 3    │                 │ │
│  │  │(Bank)│         │(Hosp)│         │(Telco)                 │ │
│  │  └──────┘         └──────┘         └──────┘                 │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### **2.2 Detection Pipeline Detailed Flow**

```
┌─────────────────────────────────────────────────────────────────┐
│         NETWORK FLOW DETECTION PIPELINE (Per Flow)              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 1: CAPTURE & AGGREGATION                                 │
│  ─────────────────────────────────────────────────────────────  │
│  Individual packets → Flow Aggregation (bidirectional)          │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐           │
│  │ Packet 1     │ │ Packet 2     │ │ Packet N     │           │
│  │ →DestA:5000 │ │ →DestB:80    │ │ ←SourceA:1024│           │
│  └──────────────┘ └──────────────┘ └──────────────┘           │
│         │                │                │                    │
│         └────────────────┼────────────────┘                    │
│                          │                                     │
│              ┌───────────▼─────────────┐                       │
│              │ NetworkFlow Object      │                       │
│              │ (bidirectional aggregate)                       │
│              │ src_ip, dst_ip, bytes,  │                       │
│              │ packets, flags, durations                       │
│              └───────────┬─────────────┘                       │
│                          │                                     │
│  STEP 2: FEATURE ENGINEERING                                  │
│  ─────────────────────────────────────────────────────────────  │
│                          │                                     │
│  From flow, extract 80+ features:                              │
│  ├─ Flow Duration                                              │
│  ├─ Packet/Byte Ratios                                        │
│  ├─ Flag Counts (SYN, ACK, FIN, RST, ...)                     │
│  ├─ Inter-Arrival Times (IAT)                                 │
│  ├─ Window Sizes                                              │
│  ├─ Protocol Statistics                                        │
│  └─ Host-based Statistics                                      │
│                          │                                     │
│              ┌───────────▼─────────────┐                       │
│              │ Feature Vector (80-D)   │                       │
│              │ x = [x₁, x₂, ..., x₈₀]│                       │
│              └───────────┬─────────────┘                       │
│                          │                                     │
│  STEP 3: PREPROCESSING                                        │
│  ─────────────────────────────────────────────────────────────  │
│                          │                                     │
│  ├─ Handle NaN: fill with median                              │
│  ├─ Handle Inf: clip to max finite value                      │
│  ├─ Normalize: StandardScaler (fit on training data)          │
│  │  x_normalized = (x - μ) / σ                                │
│  ├─ Clip: limit to ±3σ (remove extreme outliers)             │
│  └─ Result: normalized feature vector                         │
│                          │                                     │
│              ┌───────────▼──────────────────┐                  │
│              │ Preprocessed Features        │                  │
│              │ x' = StandardScaler(x)       │                  │
│              └───────────┬──────────────────┘                  │
│                          │                                     │
│  STEP 4: PARALLEL DETECTION MODELS                            │
│  ─────────────────────────────────────────────────────────────  │
│                          │                                     │
│          ┌───────────────┼───────────────┬───────────────┐     │
│          │               │               │               │     │
│   ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐       │     │
│   │  XGBoost    │ │  LSTM       │ │  Autoencoder│       │     │
│   │  Classifier │ │  Detector   │ │  (Anomaly)  │       │     │
│   │             │ │             │ │             │       │     │
│   │ Output:     │ │ Output:     │ │ Output:     │       │     │
│   │ - class     │ │ - class     │ │ - recon_err │       │     │
│   │ - prob=0.85 │ │ - prob=0.78 │ │ - err=0.65  │       │     │
│   └──────┬──────┘ └──────┬──────┘ └──────┬──────┘       │     │
│          │               │               │               │     │
│          └───────────────┼───────────────┴───────────────┘     │
│                          │                                     │
│  STEP 5: ENSEMBLE AGGREGATION                                 │
│  ─────────────────────────────────────────────────────────────  │
│                          │                                     │
│  Ensemble Score = 0.4 × P(XGBoost) +                          │
│                   0.3 × P(LSTM) +                             │
│                   0.3 × P(Autoencoder)                        │
│                 = 0.4 × 0.85 + 0.3 × 0.78 + 0.3 × 0.65      │
│                 = 0.770                                        │
│                          │                                     │
│              ┌───────────▼──────────────┐                      │
│              │ Ensemble Score: 0.770    │                      │
│              │ Decision: ATTACK (>0.5)  │                      │
│              └───────────┬──────────────┘                      │
│                          │                                     │
│  STEP 6: ZERO-DAY DETECTION (Parallel)                        │
│  ─────────────────────────────────────────────────────────────  │
│                          │                                     │
│  ├─ Reconstruction Error  → Score: 0.75 ✓ Anomalous         │
│  ├─ Isolation Forest      → Score: 0.68 ✓ Suspicious        │
│  ├─ Statistical (Z-score) → Score: 3.2 std ✓ Anomalous      │
│  ├─ Baseline Deviation    → Score: 0.82 ✓ Deviation        │
│  ├─ Temporal Spike        → Score: 0.45   Normal            │
│  └─ Entropy Analysis      → Score: 0.55 ✓ Low entropy       │
│                          │                                     │
│  Ensemble Anomaly Score = average([0.75, 0.68, 0.82, 0.55]) │
│                         = 0.70 (ANOMALOUS)                    │
│                          │                                     │
│              ┌───────────▼──────────────────┐                  │
│              │ Zero-Day Score: 0.70         │                  │
│              │ Status: ANOMALY DETECTED     │                  │
│              └───────────┬──────────────────┘                  │
│                          │                                     │
│  STEP 7: BEHAVIORAL BASELINE CHECK                            │
│  ─────────────────────────────────────────────────────────────  │
│                          │                                     │
│  Host: 192.168.1.50                                           │
│  Protocol: TCP                                                 │
│  Time: 14:30 (business hours)                                 │
│                          │                                     │
│  Baseline comparison:                                          │
│  ├─ Normal bytes/min: 100KB (mean±2std)                      │
│  ├─ Current flow: 500MB/min                                   │
│  ├─ Deviation: 5000x normal!                                  │
│  └─ Conclusion: BASELINE VIOLATION ✓                          │
│                          │                                     │
│  STEP 8: RESULT AGGREGATION                                   │
│  ─────────────────────────────────────────────────────────────  │
│                          │                                     │
│  ┌──────────────────────────────────────┐                     │
│  │ Final Detection Result:              │                     │
│  ├─────────────────────────────────────┤                     │
│  │ is_attack: TRUE                     │                     │
│  │ attack_type: "DDoS"                 │                     │
│  │ ml_confidence: 0.77                 │                     │
│  │ anomaly_score: 0.70                 │                     │
│  │ baseline_deviation: 0.95             │                     │
│  │ final_confidence: 0.87 (ensemble)   │                     │
│  │ severity: "CRITICAL"                │                     │
│  │ model_used: "ensemble+zero_day"     │                     │
│  └──────────────────────────────────────┘                     │
│                          │                                     │
│  STEP 9: EXPLAINABILITY (SHAP)                                │
│  ─────────────────────────────────────────────────────────────  │
│                          │                                     │
│  SHAP Feature Importance:                                      │
│  ├─ bytes_per_second: +0.42 ✓ (Attack indicator)            │
│  ├─ packet_rate: +0.28 ✓ (Abnormal)                        │
│  ├─ dst_port: +0.12 ✓ (Non-standard)                        │
│  ├─ flag_distribution: -0.15 (Normal pattern)               │
│  └─ window_size: -0.05 (Normal)                             │
│                          │                                     │
│  Reasoning: "High bytes/second rate at port 53               │
│  indicates probable DDoS attack"                              │
│                          │                                     │
│  STEP 10: ALERT GENERATION & RESPONSE                         │
│  ─────────────────────────────────────────────────────────────  │
│                          │                                     │
│  Create Alert:                                                 │
│  ├─ Timestamp: 2026-01-28 14:32:15 UTC                       │
│  ├─ Source: 203.0.113.50:53215                               │
│  ├─ Destination: 192.0.2.1:53                                │
│  ├─ Type: DDoS                                                │
│  ├─ Severity: CRITICAL                                        │
│  ├─ Confidence: 87%                                           │
│  └─ Explanation: SHAP values                                  │
│                          │                                     │
│  Execute Response (if severity > threshold):                  │
│  └─ BLOCK IP: 203.0.113.50 (24 hour block)                   │
│                          │                                     │
│              ┌───────────▼──────────────────┐                  │
│              │ Alert Stored in Database     │                  │
│              │ Response Executed            │                  │
│              │ Dashboard Notified           │                  │
│              │ SOC Alerted                  │                  │
│              └──────────────────────────────┘                  │
│                          │                                     │
└──────────────────────────┼─────────────────────────────────────┘
                           │
                   Repeat for next flow
```

---

## 3. Data Flow Analysis

### **3.1 End-to-End Data Flow**

```
┌─────────────────────────────────────────────────────────────────┐
│  COMPLETE DATA JOURNEY THROUGH AI-NIDS                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Physical Network                                               │
│  └─ Real packets on wire                                       │
│     │                                                           │
│     ├─► Packet Capture (Scapy/PyShark)                        │
│     │   ├─ Sniff packets from interface                       │
│     │   ├─ Extract headers (IP, TCP, UDP)                     │
│     │   └─ Parse payloads (if needed)                         │
│     │                                                           │
│     └─► Captured Packets (CapturedPacket objects)             │
│         └─ timestamp, src_ip, dst_ip, src_port, dst_port,   │
│            protocol, length, flags, payload                   │
│                                                                 │
│  Flow Aggregation                                              │
│  └─ Individual packets → Bidirectional flows                   │
│     │                                                           │
│     ├─► FlowKey (canonical identifier)                        │
│     │   └─ src_ip, src_port, dst_ip, dst_port, protocol     │
│     │                                                           │
│     └─► NetworkFlow (aggregated statistics)                   │
│         ├─ Duration: sum of packet times                      │
│         ├─ Total packets: fwd + bwd                           │
│         ├─ Total bytes: fwd + bwd                             │
│         ├─ Flag counts: SYN, ACK, FIN, RST, etc.             │
│         ├─ Inter-arrival times (IAT)                          │
│         └─ Window sizes, payload lengths, etc.                │
│                                                                 │
│  Feature Engineering                                           │
│  └─ Raw statistics → ML-ready features (80D)                  │
│     │                                                           │
│     ├─► Flow-level features                                   │
│     │   ├─ Normalized bytes/second                            │
│     │   ├─ Packet rate                                        │
│     │   ├─ Protocol ratios                                    │
│     │   └─ Statistical summaries (mean, std, max, min)       │
│     │                                                           │
│     └─► Feature Vector                                         │
│         └─ x = [f₁, f₂, ..., f₈₀] (numeric array)            │
│                                                                 │
│  Data Preprocessing                                            │
│  └─ Raw features → Normalized, standardized                   │
│     │                                                           │
│     ├─► Clean data                                            │
│     │   ├─ Replace NaN with median                            │
│     │   ├─ Replace Inf with max value                         │
│     │   └─ Remove duplicates                                  │
│     │                                                           │
│     ├─► Normalize                                             │
│     │   ├─ StandardScaler: (x - μ) / σ                       │
│     │   ├─ Clip extremes (>3σ)                               │
│     │   └─ Save scaler for inference                          │
│     │                                                           │
│     └─► Preprocessed Features                                 │
│         └─ x_norm = [normalized features]                     │
│                                                                 │
│  Model Inference (Parallel)                                    │
│  └─ Features → Detection probabilities                         │
│     │                                                           │
│     ├─► XGBoost.predict(x_norm)                              │
│     │   └─ Returns: attack_class, probability                 │
│     │                                                           │
│     ├─► LSTM.predict(sequence)                               │
│     │   └─ Returns: attack_class, probability                 │
│     │                                                           │
│     ├─► Autoencoder.predict(x_norm)                          │
│     │   ├─ Encode: x_norm → latent_code                      │
│     │   ├─ Decode: latent_code → x_reconstructed            │
│     │   └─ Returns: reconstruction_error = MSE(x, x_recon)  │
│     │                                                           │
│     └─► Zero-Day Detectors                                    │
│         ├─ Isolation Forest                                   │
│         ├─ Statistical (Z-score)                             │
│         ├─ Baseline deviation                                │
│         ├─ Temporal spike                                    │
│         └─ Each returns: anomaly_score                        │
│                                                                 │
│  Result Aggregation                                           │
│  └─ Individual predictions → Final decision                   │
│     │                                                           │
│     ├─► Ensemble Voting                                       │
│     │   └─ Weighted average of model predictions              │
│     │                                                           │
│     ├─► Confidence Calculation                                │
│     │   └─ Agreement among models                             │
│     │                                                           │
│     └─► Final Score                                           │
│         └─ ensemble_score ∈ [0.0, 1.0]                       │
│                                                                 │
│  Alert Generation                                              │
│  └─ Score > threshold → Create Alert                          │
│     │                                                           │
│     ├─► Alert Object                                          │
│     │   ├─ timestamp                                          │
│     │   ├─ source_ip, source_port                            │
│     │   ├─ destination_ip, destination_port                  │
│     │   ├─ protocol                                           │
│     │   ├─ attack_type                                        │
│     │   ├─ severity (derived from confidence)                │
│     │   ├─ confidence                                         │
│     │   ├─ risk_score                                         │
│     │   ├─ model_used                                         │
│     │   ├─ shap_explanation (feature importance)             │
│     │   └─ raw_data (serialized flow)                        │
│     │                                                           │
│     └─► Database Storage                                      │
│         └─ INSERT INTO alerts (...)                           │
│            ├─ Indexed by: severity, timestamp, type          │
│            ├─ Indexed by: source_ip, destination_ip          │
│            └─ Queryable within milliseconds                   │
│                                                                 │
│  Dashboard Visualization                                      │
│  └─ Database → Real-time UI updates                           │
│     │                                                           │
│     ├─► Query recent alerts                                   │
│     │   └─ SELECT * FROM alerts WHERE timestamp > now-1h    │
│     │                                                           │
│     ├─► Aggregate statistics                                  │
│     │   ├─ COUNT by severity                                  │
│     │   ├─ COUNT by attack_type                              │
│     │   └─ Unique source IPs                                 │
│     │                                                           │
│     ├─► Render charts                                         │
│     │   ├─ Alerts per hour (timeline)                        │
│     │   ├─ Attack distribution (pie chart)                   │
│     │   ├─ Top source IPs (bar chart)                        │
│     │   └─ Severity breakdown (gauge)                        │
│     │                                                           │
│     └─► User Interface (HTML)                                 │
│         └─ JavaScript refreshes every 5-10 seconds           │
│                                                                 │
│  User Action (Response)                                        │
│  └─ SOC analyst reviews alert and takes action                │
│     │                                                           │
│     ├─► Review Details                                        │
│     │   ├─ View full alert data                              │
│     │   ├─ Read SHAP explanation                             │
│     │   ├─ See similar past alerts                           │
│     │   └─ Assess confidence and risk                        │
│     │                                                           │
│     ├─► Decide Action                                         │
│     │   ├─ False positive → Mark resolved                    │
│     │   ├─ True attack → Execute response                    │
│     │   └─ Uncertain → Capture more data                     │
│     │                                                           │
│     └─► Execute Response                                      │
│         ├─ ResponseEngine.execute()                          │
│         ├─ Create firewall rule                              │
│         ├─ Block/throttle/quarantine                         │
│         └─ Log response in database                          │
│                                                                 │
│  Federated Learning (Optional)                                │
│  └─ Detect new patterns → Share with other organizations     │
│     │                                                           │
│     ├─► Local Training                                        │
│     │   ├─ Client trains on own data                         │
│     │   ├─ Computes weight delta                             │
│     │   └─ Calculates training metrics                       │
│     │                                                           │
│     ├─► Secure Transmission                                   │
│     │   ├─ Encrypt gradients with differential privacy      │
│     │   ├─ Apply Byzantine detection masking                │
│     │   └─ Send only deltas (NO raw data!)                  │
│     │                                                           │
│     ├─► Server Aggregation                                    │
│     │   ├─ Collect updates from all clients                  │
│     │   ├─ Weighted average (by sample count)                │
│     │   ├─ Detect and exclude malicious clients              │
│     │   └─ Add differential privacy noise                    │
│     │                                                           │
│     └─► Model Distribution                                    │
│         ├─ Broadcast aggregated model to all clients        │
│         ├─ All organizations get improved model              │
│         ├─ Each has learned from all others                  │
│         └─ Privacy maintained: no data shared                │
│                                                                 │
│  Continuous Monitoring                                         │
│  └─ System performance metrics tracked                         │
│     │                                                           │
│     ├─► Detection metrics                                     │
│     │   ├─ Detection latency (ms per flow)                   │
│     │   ├─ Model accuracy vs ground truth                    │
│     │   ├─ False positive rate                               │
│     │   └─ True positive rate                                │
│     │                                                           │
│     ├─► System health                                         │
│     │   ├─ CPU/memory/disk utilization                       │
│     │   ├─ Database query performance                        │
│     │   ├─ API response times                                │
│     │   └─ Capture packet loss %                             │
│     │                                                           │
│     └─► Stored in SystemMetrics table                         │
│         └─ Accessible via analytics dashboard                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Technical Considerations

### **4.1 Performance Optimizations**

**Detection Latency:**
- Per-flow detection: ~50-200ms (depending on model size)
- Batch detection: ~10ms per flow (amortized)
- Database query: <10ms (with proper indexing)
- Total pipeline: <250ms from packet capture to database

**Optimization Techniques:**
1. **Model Quantization**: Convert float32 to int8 (4x faster)
2. **Batch Processing**: Process multiple flows together
3. **Caching**: Cache preprocessor, models in memory
4. **Database Indexing**: Composite indices on common queries
5. **Asynchronous I/O**: Non-blocking database writes

### **4.2 Scalability Architecture**

```
Single Instance (Development):
└─ 1 process, 1 thread per model
   └ ~100 flows/sec max

Horizontal Scaling (Production):
├─ Load Balancer
│  └─ Distributes traffic across multiple instances
│
├─ Instance 1: Detection Engine 1
├─ Instance 2: Detection Engine 2
├─ Instance N: Detection Engine N
│  └─ Each independent, all write to shared DB
│
├─ Shared Database (PostgreSQL with replication)
│  └─ Handles concurrent writes efficiently
│
└─ Redis Cache (optional)
   └─ Cache preprocessor, recent models
   └─ Session storage for users
```

### **4.3 Security Considerations**

**Authentication:**
- Username/password with bcrypt hashing
- Session management with Flask-Login
- Optional: LDAP/Active Directory integration
- Optional: OAuth2 / SAML

**Authorization:**
- Role-based access control (RBAC)
- Admin, Analyst, Viewer roles
- API key authentication for programmatic access

**Network Security:**
- HTTPS/TLS for all traffic
- CORS configured for API endpoints
- CSRF protection enabled by default
- SQL injection prevention (SQLAlchemy ORM)

**Data Protection:**
- Differential privacy in federated learning
- Secure aggregation masking protocols
- Encrypted gradient transmission
- No raw network data sent to federated server

### **4.4 Reliability & Fault Tolerance**

**High Availability:**
- Database replication (master-slave)
- Load balancer with health checks
- Graceful degradation if components fail
- Alert persistence even if server is down

**Monitoring:**
- Prometheus metrics exported
- Grafana dashboards for visualization
- Alert thresholds on system health
- Automatic alerting if detection latency exceeds threshold

### **4.5 Model Management**

**Version Control:**
- Each model saved with version number
- Training date, accuracy metrics recorded
- Easy rollback to previous models
- A/B testing support

**Retraining Workflow:**
- Automatic retraining trigger:
  - Monthly (scheduled)
  - Manual (on-demand)
  - When accuracy drops below threshold
- Validation on hold-out test set before deployment
- Gradual rollout (canary deployment)

---

## Summary

The AI-NIDS system represents a sophisticated integration of multiple security technologies:

1. **Real-Time Collection**: Captures network traffic through live sniffing and PCAP analysis
2. **Intelligent Detection**: Uses ensemble ML models + zero-day anomaly detection
3. **Behavioral Analysis**: Maintains per-host, per-subnet baselines
4. **Automated Response**: Scales response based on threat confidence
5. **Federated Learning**: Enables collaborative threat detection across organizations without sharing raw data
6. **User-Friendly Interface**: Web dashboard with real-time alerts and detailed explainability

The system architecture prioritizes **accuracy**, **privacy**, **scalability**, and **usability** to provide SOC teams with actionable threat intelligence at network speed.

---

**Document prepared for:** Technical Review and Implementation Guidance  
**Recommended audience:** Security Engineers, System Architects, Operations Teams, SOC Management
