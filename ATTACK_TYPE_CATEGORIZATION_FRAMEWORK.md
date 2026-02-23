# Attack Type Categorization Framework for Zero-Day Monitoring

## Executive Summary

The AI-NIDS system categorizes attack types using a **multi-dimensional classification approach** that combines:
1. **Network behavioral characteristics** (flow patterns)
2. **Severity-based threat levels** (impact classification)
3. **MITRE ATT&CK tactics & techniques** (attack framework mapping)
4. **Indicator-based detection signatures** (anomaly indicators)
5. **Confidence scoring factors** (ensemble agreement)

---

## 1. Categorization Basis & Dimensions

### 1.1 Primary Categorization by Attack Family

The system organizes attacks into **logical families** based on similar operational characteristics:

```
┌─────────────────────────────────────────────────────────────────┐
│             ATTACK CATEGORIZATION HIERARCHY                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ├─ NETWORK-LEVEL ATTACKS (Layer 3-4)                           │
│  │  ├─ DDoS (Distributed Denial of Service)                     │
│  │  │  └─ Indicators: High packet rate, amplification, flooding │
│  │  ├─ DoS (Denial of Service)                                  │
│  │  │  └─ Indicators: Resource exhaustion, SYN floods           │
│  │  └─ Port Scan / Reconnaissance                               │
│  │     └─ Indicators: Sequential port probing, service enum     │
│  │                                                               │
│  ├─ APPLICATION-LEVEL ATTACKS (Layer 7)                         │
│  │  ├─ SQL Injection                                            │
│  │  │  └─ Indicators: Database exploitation, payload analysis   │
│  │  ├─ XSS (Cross-Site Scripting)                               │
│  │  │  └─ Indicators: Script injection, DOM manipulation        │
│  │  ├─ Command Injection                                        │
│  │  │  └─ Indicators: OS command execution attempts             │
│  │  └─ Path Traversal                                           │
│  │     └─ Indicators: Directory escape sequences (../)          │
│  │                                                               │
│  ├─ CREDENTIAL-BASED ATTACKS                                    │
│  │  ├─ Brute Force (SSH, FTP, RDP)                              │
│  │  │  └─ Indicators: Multiple failed auth, repeated attempts   │
│  │  └─ Phishing                                                 │
│  │     └─ Indicators: Social engineering, credential theft      │
│  │                                                               │
│  ├─ PAYLOAD-BASED ATTACKS                                       │
│  │  ├─ Malware/Trojans                                          │
│  │  │  └─ Indicators: Executable delivery, C2 beaconing        │
│  │  ├─ Ransomware                                               │
│  │  │  └─ Indicators: Encryption behavior, ransom notes         │
│  │  ├─ Rootkit                                                  │
│  │  │  └─ Indicators: Kernel-level persistence                 │
│  │  └─ Worm/Botnet                                              │
│  │     └─ Indicators: Self-propagation, botnet communication    │
│  │                                                               │
│  ├─ DATA BREACH ATTACKS                                         │
│  │  ├─ Data Exfiltration                                        │
│  │  │  └─ Indicators: High bytes out, unusual destinations      │
│  │  └─ Infiltration                                             │
│  │     └─ Indicators: Persistent access, internal movement      │
│  │                                                               │
│  ├─ LATERAL MOVEMENT & PERSISTENCE                              │
│  │  ├─ Lateral Movement                                         │
│  │  │  └─ Indicators: Internal-to-internal traffic, port scan   │
│  │  ├─ Privilege Escalation                                     │
│  │  │  └─ Indicators: Exploit attempts, sudo/runas abuse        │
│  │  └─ Persistence Mechanisms                                   │
│  │     └─ Indicators: Scheduled tasks, registry mods, backdoors │
│  │                                                               │
│  └─ ZERO-DAY / UNKNOWN ATTACKS                                  │
│     └─ Indicators: No signature match, anomalous behavior       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Severity-Based Classification

### 2.1 Severity Thresholds

Attacks are mapped to severity levels based on **potential impact** and **confidence scores**:

```python
# From config.py - SEVERITY_THRESHOLDS
SEVERITY_LEVELS = {
    'CRITICAL': confidence >= 0.90,     # Immediate threat to business continuity
    'HIGH':     confidence >= 0.70,     # Significant threat to confidentiality/integrity
    'MEDIUM':   confidence >= 0.50,     # Moderate threat, investigation needed
    'LOW':      confidence >= 0.30,     # Minor threat, monitored
    'INFO':     confidence >= 0.00      # Informational, routine observation
}
```

### 2.2 Attack Type to Severity Mapping

```python
# From detection/detector.py - SEVERITY_MAP
SEVERITY_MAP = {
    # CRITICAL threats (most severe)
    'DDoS':              ThreatSeverity.CRITICAL,
    'Bot':               ThreatSeverity.CRITICAL,
    'Infiltration':      ThreatSeverity.CRITICAL,
    'SQL Injection':     ThreatSeverity.CRITICAL,
    'Heartbleed':        ThreatSeverity.CRITICAL,
    'Exploits':          ThreatSeverity.CRITICAL,
    'Shellcode':         ThreatSeverity.CRITICAL,
    'Worms':             ThreatSeverity.CRITICAL,
    'Backdoor':          ThreatSeverity.CRITICAL,
    
    # HIGH threats (significant impact)
    'DoS':               ThreatSeverity.HIGH,
    'Brute Force':       ThreatSeverity.HIGH,
    'SSH-Patator':       ThreatSeverity.HIGH,
    'FTP-Patator':       ThreatSeverity.HIGH,
    'Web Attack':        ThreatSeverity.HIGH,
    'Phishing':          ThreatSeverity.HIGH,
    'Data Exfiltration': ThreatSeverity.HIGH,
    
    # MEDIUM threats (moderate impact)
    'XSS':               ThreatSeverity.MEDIUM,
    'Fuzzers':           ThreatSeverity.MEDIUM,
    'Generic':           ThreatSeverity.MEDIUM,
    'Analysis':          ThreatSeverity.MEDIUM,
    
    # LOW threats (minimal impact)
    'PortScan':          ThreatSeverity.LOW,
    'Reconnaissance':    ThreatSeverity.LOW,
    
    # INFO (normal traffic)
    'Benign':            ThreatSeverity.INFO
}
```

### 2.3 Severity Basis

**CRITICAL** attacks are classified by:
- Direct impact on business continuity
- Data confidentiality/integrity violations
- System compromise potential
- Example: DDoS makes services unavailable

**HIGH** attacks by:
- Potential for system compromise
- Authentication bypass capability
- Data exfiltration risk
- Example: Brute force allows unauthorized access

**MEDIUM** attacks by:
- Potential for exploitation with additional steps
- Limited direct impact without escalation
- Example: XSS requires user interaction

**LOW** attacks by:
- Reconnaissance nature (information gathering)
- Limited immediate threat
- Example: Port scan reveals network topology

---

## 3. MITRE ATT&CK Framework Integration

### 3.1 Tactic-to-Attack Mapping

Attacks are mapped to **MITRE ATT&CK tactics & techniques** for standardized threat classification:

```python
# From utils/seed_data.py - Attack type definitions with MITRE mappings
ATTACK_TYPES = [
    # Reconnaissance
    {'name': 'Port Scan',         'mitre': 'T1046', 'tactic': 'Reconnaissance'},
    
    # Initial Access
    {'name': 'Phishing',          'mitre': 'T1566', 'tactic': 'Initial Access'},
    
    # Execution
    {'name': 'Command Injection', 'mitre': 'T1059', 'tactic': 'Execution'},
    
    # Persistence
    {'name': 'Backdoor',          'mitre': 'T1547', 'tactic': 'Persistence'},
    
    # Privilege Escalation
    {'name': 'SQL Injection',     'mitre': 'T1190', 'tactic': 'Privilege Escalation'},
    
    # Defense Evasion
    {'name': 'Encrypted Tunnel',  'mitre': 'T1008', 'tactic': 'Defense Evasion'},
    
    # Credential Access
    {'name': 'Brute Force',       'mitre': 'T1110', 'tactic': 'Credential Access'},
    
    # Discovery
    {'name': 'Network Sweep',     'mitre': 'T1018', 'tactic': 'Discovery'},
    
    # Lateral Movement
    {'name': 'Lateral Movement',  'mitre': 'T1570', 'tactic': 'Lateral Movement'},
    
    # Collection
    {'name': 'Data Exfiltration', 'mitre': 'T1041', 'tactic': 'Exfiltration'},
    
    # Command & Control
    {'name': 'C2 Beacon',         'mitre': 'T1071', 'tactic': 'Command & Control'},
    
    # Impact
    {'name': 'DDoS',              'mitre': 'T1498', 'tactic': 'Impact'}
]
```

### 3.2 MITRE Tactic Reference

| MITRE Tactic | Example Attacks | Detection Focus |
|--------------|-----------------|-----------------|
| **Reconnaissance** (T1046, T1018) | Port scan, network sweep | Enumeration patterns, sweeps |
| **Initial Access** (T1566, T1200) | Phishing, exploit delivery | Malicious payloads, social eng |
| **Execution** (T1059, T1072) | Command injection, scripts | Executable delivery, execution |
| **Persistence** (T1547, T1037) | Backdoors, scheduled tasks | Long-term access artifacts |
| **Privilege Escalation** (T1190, T1134) | Exploits, UAC bypass | Privilege boundary violations |
| **Defense Evasion** (T1008, T1036) | Encryption, obfuscation | Hiding techniques, anti-forensics |
| **Credential Access** (T1110, T1056) | Brute force, keyloggers | Auth failures, credential theft |
| **Discovery** (T1018, T1217) | OS/service fingerprinting | System reconnaissance attempts |
| **Lateral Movement** (T1570, T1021) | RDP/SSH exploitation | Internal-to-internal traffic |
| **Collection** (T1123, T1119) | Data staging, exfiltration prep | Large outbound transfers |
| **Exfiltration** (T1041, T1048) | Data exfiltration, tunneling | Unusual data transfer patterns |
| **Command & Control** (T1071, T1092) | C2 beaconing, DNS tunneling | Periodic callbacks, protocol anomalies |
| **Impact** (T1498, T1561) | DDoS, ransomware, wiper | Resource exhaustion, destruction |

---

## 4. Indicator-Based Attack Signatures

### 4.1 Network Behavior Indicators

The system uses **signature-based indicators** to classify zero-day attacks:

```python
# From detection/zero_day_confidence.py - AttackTypeClassifier.ATTACK_SIGNATURES

ATTACK_SIGNATURES = {
    'data_exfiltration': {
        'indicators': [
            'high_bytes_out',           # >1MB outbound traffic
            'unusual_destinations',      # Non-whitelist destinations
            'off_hours_activity',        # Traffic outside business hours
            'encrypted_traffic'          # TLS/SSL encryption masking
        ],
        'weight': 0.25,
    },
    
    'ddos': {
        'indicators': [
            'high_packet_rate',         # >10,000 packets
            'high_flow_count',          # >100 concurrent flows
            'amplification_traffic',    # DNS/NTP/SNMP amplification
            'synchronized_flows'        # Coordinated traffic patterns
        ],
        'weight': 0.25,
    },
    
    'lateral_movement': {
        'indicators': [
            'internal_to_internal',     # Internal IP to internal IP
            'port_scanning',            # Sequential port access
            'protocol_probing',         # Protocol variation attempts
            'credential_testing'        # Repeated auth on port 22/3389/445
        ],
        'weight': 0.20,
    },
    
    'malware_c2': {
        'indicators': [
            'known_c2_connection',      # Threat intel lookup
            'periodic_beaconing',       # Regular callback pattern
            'dns_tunneling',            # DNS protocol abuse
            'encrypted_payload'         # TLS encrypted communication
        ],
        'weight': 0.20,
    },
    
    'reconnaissance': {
        'indicators': [
            'port_scan',                # Sequential port probing
            'network_sweep',            # Multiple IP targeting
            'service_enumeration',      # Version probing
            'version_probing'           # Service identification attempts
        ],
        'weight': 0.15,
    }
}
```

### 4.2 Indicator Thresholds

```python
# Specific indicator thresholds from zero_day_confidence.py

high_bytes_out:     bytes_sent > 1,000,000           # 1MB threshold
high_packet_rate:   packets > 10,000                 # High-speed flooding
high_flow_count:    concurrent_flows > 100          # Multiple simultaneous flows
amplification_src:  src_port in [53, 123, 161]      # DNS, NTP, SNMP
credential_ports:   dst_port in [22, 3389, 445]     # SSH, RDP, SMB
encrypted_proto:    protocol in ['tls', 'ssl']      # Encryption indicators
dns_tunneling:      protocol == 'dns' && bytes > 1000
```

---

## 5. Confidence-Based Classification

### 5.1 Confidence Factors

The system computes a **multi-factor confidence score** combining:

```python
# From detection/zero_day_confidence.py - ConfidenceScoringEngine

FACTOR_WEIGHTS = {
    'MODEL_AGREEMENT':        0.25,   # ML ensemble agreement
    'SEVERITY_SCORE':         0.20,   # Baseline severity
    'BASELINE_DEVIATION':     0.20,   # Deviation from normal
    'KNOWN_FALSE_POSITIVE':  -0.20,   # Known FP patterns
    'CONTEXTUAL_FIT':         0.15,   # Behavioral context
    'TEMPORAL_PATTERN':       0.10,   # Time-based patterns
    'PAYLOAD_ANALYSIS':       0.05,   # Payload inspection
    'GEOGRAPHIC_CONTEXT':     0.05,   # IP geolocation
}

# Confidence Score Formula:
CONFIDENCE = Σ(Factor_Value × Factor_Weight)
```

### 5.2 Confidence Classification

```
Confidence >= 0.90: CRITICAL severity assigned
Confidence 0.70-0.89: HIGH severity assigned
Confidence 0.50-0.69: MEDIUM severity assigned
Confidence 0.30-0.49: LOW severity assigned
Confidence < 0.30: INFO level or not an attack
```

### 5.3 Multi-Model Ensemble Voting

Attack type is determined by **ensemble agreement** across three models:

```
┌──────────────────────────────────────────────────────┐
│         ML ENSEMBLE ATTACK CLASSIFICATION            │
├──────────────────────────────────────────────────────┤
│                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │  XGBoost    │  │ Autoencoder │  │    LSTM    │  │
│  │  Classifier │  │ Anomaly     │  │  Sequence  │  │
│  │ (40% weight)│  │ (30% weight)│  │ (30% wt)   │  │
│  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘  │
│         │                │                │         │
│         └────────────────┼────────────────┘         │
│                          │                          │
│                    ┌─────▼─────┐                    │
│                    │  Weighted  │                    │
│                    │  Ensemble  │                    │
│                    │  Voting    │                    │
│                    └─────┬─────┘                    │
│                          │                          │
│          ┌───────────────▼───────────────┐          │
│          │  Attack Type Classification   │          │
│          │  - Primary Type (highest %)   │          │
│          │  - Confidence Score           │          │
│          │  - Secondary Types (ranked)   │          │
│          └───────────────────────────────┘          │
│                                                      │
└──────────────────────────────────────────────────────┘
```

---

## 6. Dataset-Specific Categorization

### 6.1 CICIDS2017 Attack Categories

The system trains on **CICIDS2017 dataset** with these categories:

```
ATTACK_CATEGORIES (from config.py):
├─ BENIGN (Normal Traffic)
├─ DoS Attacks
│  ├─ DoS Hulk
│  ├─ DoS GoldenEye
│  ├─ DoS slowloris
│  └─ DoS Slowhttptest
├─ DDoS
├─ PortScan (Probing)
├─ Brute Force
│  ├─ FTP-Patator
│  └─ SSH-Patator
├─ Bot/Botnet
├─ Web Attacks
│  ├─ Web Attack - Brute Force
│  ├─ Web Attack - XSS
│  └─ Web Attack - SQL Injection
├─ Infiltration
└─ Exploit
   └─ Heartbleed
```

### 6.2 UNSW-NB15 Attack Categories

Alternative training dataset includes:

```
Additional attack types:
├─ Backdoors
├─ Exploits
├─ Fuzzers
├─ Generic malware
├─ Reconnaissance
├─ Shellcode
└─ Worms
```

---

## 7. Zero-Day Attack Categorization Logic

### 7.1 Unknown Attack Identification

When an attack cannot be matched to known signatures:

```
Classification Flow for Unknown/Zero-Day:
│
├─ Step 1: Network Characteristics Analysis
│  ├─ Packet rate analysis
│  ├─ Flow duration and timing
│  ├─ Bytes sent/received ratios
│  └─ Protocol distribution
│
├─ Step 2: Behavioral Anomaly Detection
│  ├─ Autoencoder reconstruction error
│  ├─ Statistical deviation (Z-score, MAD)
│  ├─ Baseline comparison (host/subnet level)
│  └─ Temporal spike detection
│
├─ Step 3: Attack Family Classification
│  ├─ Score against data_exfiltration signature
│  ├─ Score against ddos signature
│  ├─ Score against lateral_movement signature
│  ├─ Score against malware_c2 signature
│  └─ Score against reconnaissance signature
│
├─ Step 4: Confidence Computation
│  ├─ Multi-factor confidence scoring
│  ├─ Model ensemble agreement
│  └─ Severity level assignment
│
└─ Result: (Attack_Type, Confidence, Severity, Indicators)
     Example: ('data_exfiltration', 0.92, 'CRITICAL', 
               ['high_bytes_out', 'unusual_destinations'])
```

### 7.2 Attack Type Probability Distribution

```python
# Example: Classifying unknown zero-day traffic

flow_data = {
    'bytes_out': 5_000_000,
    'protocol': 'tls',
    'dst_port': 443,
    'src_ip': '192.168.1.50',
    'dst_ip': '198.51.100.45'  # Unknown external IP
}

# Classification results:
{
    'data_exfiltration':   0.45,  # Highest probability
    'malware_c2':          0.25,  # Secondary possibility
    'lateral_movement':    0.15,
    'ddos':                0.10,
    'reconnaissance':      0.05
}

# Final Classification:
{
    'primary_type': 'data_exfiltration',
    'confidence': 0.92,
    'severity': 'CRITICAL',
    'indicators_detected': ['high_bytes_out', 'unusual_destinations', 'encrypted_traffic'],
    'secondary_types': {
        'malware_c2': 0.25,
        'lateral_movement': 0.15
    }
}
```

---

## 8. Mitigation Strategy Mapping

### 8.1 Attack Type to Mitigation Actions

Attack categorization directly determines **response actions**:

```python
# From detection/mitigation_engine.py - MITIGATION_MATRIX

MITIGATION_MATRIX = {
    'DDoS': {
        'severity_critical': [
            {'action': 'BLOCK_IP',          'priority': 1},
            {'action': 'RATE_LIMIT',        'priority': 2},
            {'action': 'ALERT_SOC',         'priority': 1},
        ]
    },
    'Port Scan': {
        'severity_high': [
            {'action': 'BLOCK_IP',          'priority': 1},
            {'action': 'INCREASE_MONITORING', 'priority': 3},
        ]
    },
    'SQL Injection': {
        'severity_critical': [
            {'action': 'ISOLATE_HOST',      'priority': 1},
            {'action': 'UPDATE_WAF',        'priority': 1},
            {'action': 'ALERT_SOC',         'priority': 1},
        ]
    },
    'Data Exfiltration': {
        'severity_critical': [
            {'action': 'BLOCK_IP',          'priority': 1},
            {'action': 'DEEP_PACKET_INSPECTION', 'priority': 2},
            {'action': 'ALERT_SOC',         'priority': 1},
        ]
    }
}
```

---

## 9. Classification Decision Tree

### 9.1 Attack Type Decision Process

```
START: Anomaly Detected
│
├─ Q1: High packet rate (>10K pps)?
│  ├─ YES: Check for amplification sources
│  │  ├─ YES (DNS/NTP/SNMP): → DDoS/Flooding
│  │  └─ NO: → DoS Attack
│  └─ NO: Continue...
│
├─ Q2: High bytes outbound (>1MB) to unknown destination?
│  ├─ YES: → Data Exfiltration
│  └─ NO: Continue...
│
├─ Q3: Multiple sequential port attempts?
│  ├─ YES: → Port Scan / Reconnaissance
│  └─ NO: Continue...
│
├─ Q4: Multiple failed authentication attempts?
│  ├─ YES: → Brute Force Attack
│  └─ NO: Continue...
│
├─ Q5: Internal-to-internal traffic with port scanning?
│  ├─ YES: → Lateral Movement
│  └─ NO: Continue...
│
├─ Q6: Known C2 IP or periodic beaconing pattern?
│  ├─ YES: → Malware/C2 Communication
│  └─ NO: Continue...
│
├─ Q7: SQL syntax in packet payload?
│  ├─ YES: → SQL Injection
│  └─ NO: Continue...
│
├─ Q8: Script tags in HTTP payload?
│  ├─ YES: → XSS Attack
│  └─ NO: Continue...
│
└─ DEFAULT: → Unknown/Anomalous (Zero-Day)
   └─ Assign based on signature matching confidence
   └─ Flag for incident investigation
```

---

## 10. Real-World Classification Examples

### Example 1: DDoS Attack Detection

```
Network Observation:
  - 50,000 packets/second (HIGH)
  - 1,000+ simultaneous flows (HIGH)
  - Source ports from DNS servers (DNS=53)
  - Target: Single port (80)
  
Classification Process:
  1. high_packet_rate: 50K > 10K ✓
  2. high_flow_count: 1000 > 100 ✓
  3. amplification_traffic: DNS (port 53) ✓
  4. synchronized_flows: Coordinated pattern ✓
  
Attack Scores:
  - ddos: 4/4 indicators = 100%
  - Other attacks: 0-20%
  
Result:
  ├─ Type: DDoS
  ├─ Confidence: 0.98
  ├─ Severity: CRITICAL
  ├─ MITRE: T1498 (Impact)
  └─ Mitigation: BLOCK_IP, RATE_LIMIT (Priority 1-2)
```

### Example 2: Data Exfiltration Detection (Zero-Day)

```
Network Observation:
  - 5MB outbound to unknown IP
  - TLS encryption (encrypted payload)
  - Off-hours activity (2:30 AM)
  - Destination: Tor exit node
  
Classification Process:
  1. high_bytes_out: 5MB > 1MB ✓
  2. unusual_destinations: Non-whitelist ✓
  3. off_hours_activity: 2:30 AM ✓
  4. encrypted_traffic: TLS ✓
  
Attack Scores:
  - data_exfiltration: 4/4 indicators = 100%
  - malware_c2: 2/4 indicators = 50%
  
Result:
  ├─ Type: Data Exfiltration
  ├─ Confidence: 0.95
  ├─ Severity: CRITICAL
  ├─ MITRE: T1041 (Exfiltration)
  ├─ Flag: ZERO-DAY (no signature match)
  └─ Mitigation: BLOCK_IP, DPI, ALERT_SOC (All Priority 1)
```

### Example 3: Lateral Movement (Zero-Day)

```
Network Observation:
  - Internal host 192.168.1.50 → Internal host 192.168.1.200
  - Probing ports: 22, 445, 3389 (SSH, SMB, RDP)
  - Multiple failed authentication attempts
  
Classification Process:
  1. internal_to_internal: Private → Private ✓
  2. port_scanning: Sequential probing ✓
  3. credential_testing: High-value ports ✓
  4. protocol_probing: Multiple protocols ✓
  
Attack Scores:
  - lateral_movement: 4/4 indicators = 100%
  - reconnaissance: 2/4 indicators = 50%
  
Result:
  ├─ Type: Lateral Movement
  ├─ Confidence: 0.93
  ├─ Severity: CRITICAL
  ├─ MITRE: T1570 (Lateral Movement)
  ├─ Flag: COMPROMISE DETECTED (post-initial access)
  └─ Mitigation: ISOLATE_HOST, ALERT_SOC, INCREASE_MONITORING (Priority 1-2)
```

---

## 11. Categorization Quality Metrics

### 11.1 Classification Accuracy Measurement

```
Precision = True Positives / (True Positives + False Positives)
  - Measures: "When we say DDoS, how often is it actually DDoS?"
  - Target: >90% for critical classifications

Recall = True Positives / (True Positives + False Negatives)
  - Measures: "How many actual DDos attacks do we catch?"
  - Target: >85% for zero-day detection

F1-Score = 2 × (Precision × Recall) / (Precision + Recall)
  - Balanced metric for imbalanced datasets
  - Target: >87% overall
```

### 11.2 False Positive Reduction

System employs techniques to minimize false positives:

```
1. Baseline Learning
   - Per-host/subnet normal patterns
   - Reduces false positives from legitimate spikes

2. Context Awareness
   - Time-of-day analysis
   - Business logic validation
   - Geographic context checks

3. Multi-Factor Confidence
   - Requires agreement across multiple indicators
   - Weights model consensus heavily (0.25)

4. Known FP Pattern Matching
   - Negative weight (-0.20) for known false positive patterns
   - Example: Backup systems generating high traffic
```

---

## 12. Attack Categorization Flowchart Summary

```
                              ┌─────────────────┐
                              │ Anomaly Detected│
                              └────────┬────────┘
                                       │
                                       ▼
                          ┌────────────────────────┐
                          │ Extract Flow Features  │
                          │ - Packet rate         │
                          │ - Bytes in/out        │
                          │ - Ports/Protocol      │
                          │ - Duration            │
                          └────────────┬───────────┘
                                       │
                                       ▼
                          ┌────────────────────────┐
                          │ Check Attack Signatures│
                          │ - DDoS signature      │
                          │ - Exfil signature     │
                          │ - Lateral Move sig    │
                          │ - C2 signature        │
                          │ - Recon signature     │
                          └────────────┬───────────┘
                                       │
                                       ▼
                          ┌────────────────────────┐
                          │ Score Each Attack Type │
                          │ (Weighted indicators)  │
                          └────────────┬───────────┘
                                       │
                                       ▼
                          ┌────────────────────────┐
                          │ Select Highest Scoring │
                          │ Attack Type            │
                          └────────────┬───────────┘
                                       │
                                       ▼
                          ┌────────────────────────┐
                          │ Compute Confidence     │
                          │ Multi-factor scoring   │
                          └────────────┬───────────┘
                                       │
                                       ▼
                          ┌────────────────────────┐
                          │ Map to Severity Level  │
                          │ & MITRE Technique      │
                          └────────────┬───────────┘
                                       │
                                       ▼
                          ┌────────────────────────┐
                          │ Generate Mitigation    │
                          │ Strategy & Alert       │
                          └────────────────────────┘
```

---

## Conclusion

The AI-NIDS attack categorization framework is **multi-dimensional**, combining:

| Dimension | Purpose | Example |
|-----------|---------|---------|
| **Behavioral** | Identify patterns | High bytes out → Exfiltration |
| **Severity** | Business impact | Critical = system compromise |
| **MITRE ATT&CK** | Standardized taxonomy | T1498 = Impact tactic |
| **Indicators** | Specific signatures | Port 22 attempts = Brute Force |
| **Confidence** | Ensemble agreement | 0.95 confidence = high certainty |

This enables:
- ✅ Accurate zero-day classification
- ✅ Precise mitigation strategy selection
- ✅ Standardized threat reporting
- ✅ Cross-organizational threat sharing
- ✅ Compliance with security frameworks

