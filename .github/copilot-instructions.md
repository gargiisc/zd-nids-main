# AI Coding Agent Instructions for AI-NIDS

## Project Overview
**AI-NIDS** is a commercial-grade Network Intrusion Detection System combining signature-based detection (Suricata), machine learning, behavioral baselines, and federated learning for zero-day detection across distributed organizations.

## Architecture

### Three-Layer Detection Stack
1. **Real-time Collectors** (`collectors/`) → PCAP files, live network capture, Suricata/Zeek logs
2. **Feature Extraction & ML Models** (`ml/`) → 80+ network flow features processed through ensemble models
3. **Detection Engine** (`detection/`) → Orchestrates multiple models, generates alerts with SHAP explainability

### Data Flow
```
Network Traffic → Collectors → Flow Extraction → Feature Engineering → 
ML Ensemble (XGBoost + Autoencoder + LSTM) → Decision (confidence + severity) → 
Alert + Explanation → Database + API
```

### Key Components
- **`collectors/`**: Packet capture (live/PCAP), Suricata/Zeek log parsing, flow extraction
- **`ml/`**: Preprocessing, training, inference, models (XGBoost, Autoencoder, LSTM, GNN)
- **`ml/models/adaptive_ensemble.py`**: Intelligent model selection based on attack type and network context
- **`detection/detector.py`**: Main orchestrator; runs all models, combines results, provides confidence scores
- **`behavior/baseline_engine.py`**: Per-host/subnet baselines for statistical anomaly detection (no ML needed)
- **`federated/`**: Federated learning for zero-day detection across multiple organizations
- **`app/`**: Flask web API with SQLAlchemy database, authentication, real-time alerts

## Critical Workflows

### Running the Application
```bash
python run.py                    # Dev mode (host:port auto-configured)
python run.py --host 0.0.0.0    # Bind to all interfaces
gunicorn wsgi:app               # Production (use Docker instead)
```

### Testing
```bash
pytest tests/ -v                # Run all tests
pytest tests/ -m "not slow"     # Exclude slow tests
pytest --cov=app,ml,detection   # Coverage report
```

### ML Model Development
1. **Data Preparation**: Load CICIDS2017 or UNSW-NB15 datasets
   ```python
   from ml.preprocessing.preprocessor import DataPreprocessor
   preprocessor = DataPreprocessor()
   X_train, X_val, X_test = preprocessor.prepare_data('data.csv')
   ```
2. **Training**: Use `ml.training.ModelTrainer`
3. **Inference**: `detection.detector.DetectionEngine.detect()` handles feature conversion & model orchestration

### Adding Network Flow Analysis
- Flow extraction happens in `collectors/pcap_handler.py` (bidirectional flow key: src_ip:src_port → dst_ip:dst_port)
- Features extracted in `NetworkFlow.to_features()`: duration, packet/byte ratios, IAT stats, flag counts
- Always add features to CICIDS2017 compatible column set (`config.py`: `FEATURE_COLUMNS`)

## Patterns & Conventions

### ML Model Structure
- **Ensemble over single model**: `detection/detector.py` runs XGBoost + Autoencoder + LSTM with confidence weighting
- **Confidence scoring**: Ensemble weighted average (`config.py`: `ENSEMBLE_WEIGHTS`); apply severity thresholds to convert to attack class
- **Attack classification**: Map ML outputs to `ThreatSeverity` enum (CRITICAL/HIGH/MEDIUM/LOW/INFO)

### Database Models
- Use SQLAlchemy ORM; keep queries indexed (`app/models/database.py`)
- `NetworkFlow` model stores raw + predicted labels; `Alert` model logs detections with SHAP explanations
- Always include `timestamp` index for time-series queries

### Federated Learning Data Flow
- **Server**: `federated/federated_server.py` aggregates encrypted gradient updates (FedAvg or FedProx)
- **Client**: `federated/federated_client.py` trains locally, computes gradients, sends to server (never raw data)
- **Privacy**: `federated/secure_aggregator.py` adds differential privacy noise + detects Byzantine clients
- Key files: `FEDERATED_LEARNING_ARCHITECTURE.md`, `ZERO_DAY_DETECTION_FEDERATED.md` (architecture rationale)

### Behavioral Baseline System
- `behavior/baseline_engine.py` tracks per-host/subnet/protocol statistics independently of ML
- Use for low-latency anomaly detection: "192.168.1.24 typically sends 10 DNS/min, now 500/min" → alert
- Complements ML models; can detect anomalies ML models might miss due to training data distribution

### API Design
- Public endpoints: `/detect` (flow analysis), `/threat-intel` (public threat data)
- Protected endpoints: Require API key (`@api_key_required`) or login (`@login_required`)
- Flow inference payload: `{'flows': [{'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'bytes_sent', ...}]}`

### Testing Patterns
- Use `pytest` with markers (`slow`, `integration`)
- Mock detectors in unit tests; test API responses end-to-end
- Fixtures in `tests/conftest.py`: sample flows, alerts, users

## Project-Specific Decisions

### Why Federated Learning?
- **Zero-day detection**: No signatures = need behavioral models trained across diverse traffic
- **Privacy**: Share gradients (encrypted), never raw network data across organizations
- **Resilience**: Bank compromise ≠ Hospital compromise; local data stays local

### Why Ensemble Models?
- XGBoost: Fast, interpretable, handles tabular flow features
- Autoencoder: Detects novel patterns (reconstruction error for zero-days)
- LSTM: Captures sequence patterns (port scanning = slow sequence of SYN→RST)

### Configuration Management
- `config.py` defines environment-specific settings (dev/test/prod)
- Severity thresholds, ensemble weights, anomaly detection parameters tunable per environment
- `.env` file for secrets (DATABASE_URL, API keys); `.env.example` provided

## External Dependencies
- **Network**: Scapy (packet capture), Suricata/Zeek (log parsing)
- **ML**: XGBoost, PyTorch (Autoencoder/LSTM/GNN), scikit-learn
- **Web**: Flask + SQLAlchemy
- **Explainability**: SHAP (model interpretation)
- **Threat Intel**: OTXv2 (AlienVault), VirusTotal API

## Common Tasks

### Add New Attack Type Detection
1. Create training labels in dataset
2. Retrain ensemble models
3. Add to `ThreatSeverity` severity mapping in `detection/detector.py`
4. Test with `/detect` API endpoint

### Integrate New Packet Source
1. Implement collector in `collectors/` (inherit from base if exists)
2. Extract flows using `pcap_handler.py` or parser
3. Call `detector.DetectionEngine.detect()` with flow features
4. Log alerts to database

### Debug Zero-Day Detection
1. Check baseline vs actual in `behavior/baseline_engine.py`
2. Inspect autoencoder reconstruction error
3. Review SHAP explanations in alert record
4. Consider federated client status (`federated/federated_server.py` metrics)

## Files to Read First
- [README.md](README.md) (currently empty; see docs)
- [FEDERATED_LEARNING_ARCHITECTURE.md](FEDERATED_LEARNING_ARCHITECTURE.md)
- [ZERO_DAY_DETECTION_FEDERATED.md](ZERO_DAY_DETECTION_FEDERATED.md)
- [config.py](config.py) (configuration reference)
- [detection/detector.py](detection/detector.py) (detection orchestration)
- [app/__init__.py](app/__init__.py) (Flask factory)

## Debugging Tips
- Enable Flask debug mode: `FLASK_ENV=development python run.py`
- Check logs: `data/logs/nids.log`
- Inspect database: SQLite at `data/nids.db` (or PostgreSQL in production)
- Test detector directly: `from detection.detector import DetectionEngine; engine.detect(flows)`
- Verify feature alignment: Compare CICIDS2017 dataset columns with `config.py` feature list
