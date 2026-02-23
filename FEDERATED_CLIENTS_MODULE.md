# Federated Clients Real-Time Dashboard Module

## Overview

The Federated Clients module provides real-time monitoring and visualization of all connected federated learning clients (hospitals, banks, universities, etc.) in the AI-NIDS dashboard. It displays client status, training progress, and aggregated statistics with live updates via Server-Sent Events (SSE).

## Features

### Real-Time Updates
- **Server-Sent Events (SSE)**: Bidirectional communication between clients and dashboard without page refresh
- **WebSocket Alternative**: Can be extended to use WebSockets for even more responsiveness
- **Keep-Alive**: Automatic reconnection with exponential backoff

### Client Information Display
- **Organization Name & ID**: Unique identifier for each federated client
- **Connection Status**: Online/Offline/Training with visual indicators
- **Training Round**: Current federated learning round
- **Last Update Timestamp**: When the client last reported
- **Model Metrics**: Local accuracy, loss (if available)
- **Privacy Budget (ε)**: Differential privacy spending tracker
- **Statistics**: Flows processed, attacks detected

### Dashboard Metrics
- **Total Clients**: Online/Offline count
- **Average Accuracy**: Global model performance
- **Training Convergence**: Average loss across clients
- **Active Training Rounds**: Clients currently training
- **Aggregated Flows**: Total network flows across all clients
- **Federated Detections**: Total attacks detected via consensus

### Filtering & Search
- Filter clients by status (Online, Offline, Training)
- Automatic sorting by status and organization name
- Real-time search (client cards refresh instantly)

### Scalability & Privacy
- **Metadata Only**: Only aggregated metrics and metadata exposed (no raw data)
- **Non-Blocking**: Event-driven architecture using queues
- **Efficient**: Only changed data transmitted in real-time
- **Privacy-Preserving**: ε-tracking for differential privacy

## Architecture

### Backend Components

#### API Endpoints (`app/routes/federated_clients_api.py`)

1. **`GET /api/federated-clients/list`**
   - Returns all connected clients with metadata
   - Query params: `status`, `limit`, `sort_by`
   - Response includes: organization, status, training round, metrics

2. **`GET /api/federated-clients/client/<client_id>`**
   - Detailed view for a specific client
   - Includes training history (last 100 rounds)
   - Response: client info, current stats, training trends

3. **`GET /api/federated-clients/stats`**
   - Aggregated federated statistics
   - Returns: total clients, online count, average accuracy/loss, active training rounds

4. **`POST /api/federated-clients/update-status`**
   - Called by clients to report their status
   - Expected payload:
     ```json
     {
       "client_id": "fed-abc123",
       "status": "online|training|offline",
       "training_round": 42,
       "model_accuracy": 0.96,
       "model_loss": 0.05,
       "flows_processed": 1000,
       "attacks_detected": 5
     }
     ```
   - Broadcasts update to SSE subscribers

5. **`GET /api/federated-clients/stream` (SSE)**
   - Server-Sent Events stream for real-time updates
   - Sends: `client_update` events as clients report
   - Connection established event on subscribe
   - Keep-alive comments every 30 seconds

6. **`GET /api/federated-clients/health`**
   - Health check endpoint for monitoring

#### Client Status Tracker (`ClientStatusTracker` class)

- **Tracks**: Real-time client status, metrics, and training history
- **Broadcasts**: Updates to all SSE subscribers via event queues
- **Storage**: In-memory (thread-safe with locks)
- **History**: Stores last 100 training rounds per client

### Frontend Components

#### CSS (`app/static/css/federated_clients.css`)
- **Responsive Grid**: Auto-fit client cards (320px min-width)
- **Status Indicators**: Color-coded badges with animations
- **Progress Bars**: Accuracy and privacy budget visualization
- **Card Animations**: Fade-in, pulse, and status-specific animations
- **Dark Theme**: Consistent with AI-NIDS design
- **Mobile Friendly**: Breakpoints at 1024px, 768px, 480px

#### JavaScript (`app/static/js/federated_clients.js`)

**`FederatedClientsManager` Class**

```javascript
// Initialize
fedClientsMgr = new FederatedClientsManager();

// Methods:
- connectSSE()              // Connect to SSE stream
- loadClients()              // Fetch all clients from API
- loadStats()                // Fetch aggregated stats
- handleClientUpdate(data)   // Handle real-time SSE updates
- filterAndRender(clients)   // Render with active filters
- createClientCard(client)   // Generate card HTML
- showClientDetails(id)      // Show detailed modal
```

**Features**:
- Automatic reconnection with exponential backoff
- Real-time card updates without full re-render
- Periodic fallback refresh (30s) if SSE fails
- Memory-efficient Map storage
- Client detail modal with training history

#### Template (`app/templates/zero_day_dashboard.html`)

New section with:
- Statistics grid (6 metrics)
- Status filter dropdown
- Real-time connection indicator
- Clients grid container
- Empty state and loading states

## Data Flow

```
1. Client Status Update
   Federated Client → POST /api/federated-clients/update-status
                    → Database updated (FederatedClient model)
                    → ClientStatusTracker updated
                    → Event queued for all SSE subscribers

2. Real-Time Push
   Event queued → SSE stream → Browser EventSource
               → JavaScript event listener
               → Card updated instantly

3. Periodic Sync
   JavaScript → GET /api/federated-clients/list (every 30s)
             → Reconcile with SSE updates
             → Show any missed data

4. Aggregated Stats
   Browser (on card update) → GET /api/federated-clients/stats
                            → Update dashboard metrics
```

## Database Schema

### FederatedClient Model

```python
class FederatedClient(db.Model):
    client_id: str (unique, indexed)
    organization: str
    subnet: str (CIDR)
    server_url: str
    api_key: str (hashed)
    
    # Status
    is_active: bool
    last_heartbeat: datetime
    last_training_round: datetime
    
    # Statistics
    total_flows_seen: int
    total_attacks_detected: int
    total_training_rounds: int
    
    # Model Performance
    local_accuracy: float
    local_precision: float
    local_recall: float
    
    # Privacy
    epsilon_spent: float (differential privacy budget)
    
    # Metadata
    client_metadata: str (JSON)
    created_at: datetime
    updated_at: datetime
```

## Security & Privacy

### Privacy Preservation
1. **Metadata Only**: No raw network data exposed via API
2. **Aggregated Metrics**: Only average accuracy, total flows, etc.
3. **Differential Privacy Tracking**: ε-budget monitoring per client
4. **No Raw Payloads**: Client updates contain only statistics

### Authentication
- Login required for all federated dashboard endpoints
- API key validation for client update endpoints (can be added)
- CSRF exempt for SSE stream (read-only)

### Data Minimization
- Client card shows only aggregated data
- Detailed view requires explicit action (client link)
- Training history stored in-memory (not persisted long-term)
- Event queues limited to 50 items (overflow protection)

## Usage

### For Administrators
1. Navigate to **Zero-Day Detection Dashboard**
2. Scroll to **Federated Client Network** section
3. See all connected clients with live updates
4. Filter by status: Online/Offline/Training
5. Click **Details** on any client to see training history

### For Federated Clients
1. Register with the system:
   ```bash
   curl -X POST http://ai-nids:5000/api/federated/register \
     -H "Content-Type: application/json" \
     -d '{
       "organization": "Hospital A",
       "subnet": "192.168.1.0/24",
       "server_url": "http://hospital-a.local:8001"
     }'
   ```

2. Send periodic status updates:
   ```bash
   curl -X POST http://ai-nids:5000/api/federated-clients/update-status \
     -H "Content-Type: application/json" \
     -d '{
       "client_id": "fed-hospital-001",
       "status": "training",
       "training_round": 42,
       "model_accuracy": 0.96,
       "model_loss": 0.05,
       "flows_processed": 50000,
       "attacks_detected": 12
     }'
   ```

### Testing with Simulator
```bash
# Install requests if needed
pip install requests

# Run simulator (5 min, 10s interval)
python scripts/simulate_federated_clients.py \
  --duration 300 \
  --interval 10 \
  --url http://localhost:5000
```

## Performance Considerations

### Scalability
- **SSE Queues**: One queue per subscriber (50 item limit)
- **Thread-Safe**: Locks on client status tracker
- **Memory**: ~1KB per client in tracker
- **Event Size**: ~500 bytes per update

### Limits
- **Max Clients per Page**: 100 (configurable)
- **Training History**: 100 rounds per client (oldest purged)
- **SSE Queue Size**: 50 events (overflow protection)
- **Reconnect Timeout**: 5 seconds with exponential backoff

### Optimization Tips
1. **Pagination**: Use `limit` parameter for large deployments
2. **Filtering**: Filter on server-side to reduce data transfer
3. **Update Frequency**: Keep client updates to every 10-30s
4. **Caching**: Browser caches static assets (CSS/JS)

## Troubleshooting

### SSE Connection Not Established
1. Check browser console: `console.log()` messages
2. Verify `/api/federated-clients/stream` endpoint is accessible
3. Check for proxy issues (some proxies don't support SSE)
4. Fallback to periodic refresh every 30 seconds

### Clients Not Appearing
1. Verify clients are registered: `GET /api/federated/clients/list`
2. Check last_heartbeat < 5 minutes ago
3. Ensure client IP is whitelisted if firewall rules apply
4. Verify update payload includes all required fields

### High Memory Usage
1. Reduce history size: Edit `ClientStatusTracker._training_rounds` limit
2. Reduce SSE queue size: Edit `queue.Queue(maxsize=50)`
3. Increase purge frequency or implement TTL on old records

### Slow Updates
1. Check network latency: `ping api-server`
2. Verify database indexes on `last_heartbeat`, `client_id`
3. Reduce number of clients displayed (use filter)
4. Check API response time: `/api/federated-clients/stats`

## Future Enhancements

1. **WebSocket Support**: Replace SSE with bidirectional WebSockets
2. **Client Details Modal**: Full drawer with client history graphs
3. **Predictive Alerts**: Flag clients likely to go offline
4. **Model Comparison**: Side-by-side accuracy trends
5. **Export Reports**: PDF reports of federated learning rounds
6. **Advanced Filtering**: Multi-select status, organization filters
7. **Geolocation Maps**: Visualize client locations
8. **Anomaly Detection**: Alert when client metrics deviate
9. **Client Provisioning**: UI to register and manage clients
10. **Database Persistence**: Store training history in database

## Integration Points

### With Existing Systems
- **Zero-Day Dashboard**: Federated consensus feeds into anomaly detection
- **Database Models**: Uses existing `FederatedClient` and `FederatedRound`
- **Authentication**: Inherits login system from Flask-Login
- **Styling**: Uses AI-NIDS CSS variables and Bootstrap

### External APIs
- Federated server aggregation (read-only)
- Client status updates (write)
- Threat intelligence feeds (for context)

## Files Modified/Created

### Created
- `app/routes/federated_clients_api.py` (530 lines) - API endpoints
- `app/static/css/federated_clients.css` (650 lines) - Styling
- `app/static/js/federated_clients.js` (500 lines) - Frontend logic
- `scripts/simulate_federated_clients.py` (220 lines) - Testing tool

### Modified
- `app/__init__.py` - Registered `federated_clients_bp` blueprint
- `app/templates/zero_day_dashboard.html` - Added module section

### Database
- Existing `FederatedClient` model used (no migration needed)
- Existing `FederatedRound` model for training round tracking

## API Response Examples

### GET /api/federated-clients/list
```json
{
  "total": 3,
  "clients": [
    {
      "id": "fed-hospital-001",
      "organization": "Hospital A",
      "subnet": "192.168.1.0/24",
      "status": "online",
      "connection_status": "online",
      "training_round": 42,
      "last_update": "2026-01-28T10:30:45Z",
      "local_accuracy": 0.96,
      "local_loss": 0.05,
      "flows_processed": 50000,
      "attacks_detected": 12,
      "registered_at": "2026-01-15T08:00:00Z",
      "is_online": true,
      "online_since": "2h 30m ago",
      "epsilon_spent": 0.45
    }
  ]
}
```

### POST /api/federated-clients/update-status (Success)
```json
{
  "status": "updated",
  "client_id": "fed-hospital-001"
}
```

### GET /api/federated-clients/stats
```json
{
  "total_clients": 5,
  "online_clients": 4,
  "offline_clients": 1,
  "avg_accuracy": 0.94,
  "avg_loss": 0.08,
  "total_flows_aggregated": 250000,
  "total_attacks_detected": 120,
  "active_training_rounds": 3,
  "avg_epsilon_spent": 0.32
}
```

## Support & Contact

For issues or questions:
1. Check logs: `data/logs/nids.log`
2. Review API responses for error details
3. Test with simulator: `python scripts/simulate_federated_clients.py`
4. Check database: `data/nids.db` - `federated_clients` table

## License

Part of AI-NIDS (Network Intrusion Detection System). See LICENSE file.
