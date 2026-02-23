Federated Clients — Integration Guide
=====================================

This document explains how to add federated clients to AI-NIDS and connect additional organizations so their alerts and models participate in the federation.

1) Register a Federated Client (recommended)
-------------------------------------------
Use the central server API to register clients. This returns `client_id` and `api_key`.

Example:
```bash
curl -X POST http://<SERVER>/api/federated/register \
  -H "Content-Type: application/json" \
  -d '{"organization":"Healthcare Corp","subnet":"192.168.10.0/24","server_url":"https://client.local:5001"}'
```

Response:
```json
{"client_id":"fc_...","api_key":"sk_...","server_url":"..."}
```

2) Client-side: run the federated client
----------------------------------------
A federated client should run locally at each organization. It must:
- Register with the central server (or be pre-registered by ops)
- Send periodic heartbeats to `/api/federated/heartbeat`
- Optionally forward local alerts to the central server (see forwarding)
- Accept model distribution requests from the central server

A simple client process sketch:
```python
# register -> send heartbeat -> train locally -> upload gradients
```

3) Forwarding alerts vs remote DB access
----------------------------------------
There are two common integration patterns:

A) Forward alerts (recommended)
- Each client forwards alert records (or summaries) to central API endpoints.
- Benefits: simple, firewall-friendly, central storage, no DB access required.
- Use-case: small/medium organizations.

B) Remote DB access (advanced)
- Central server connects directly to client DB to pull alerts.
- Requires network access, VPN, or a secure tunnel and DB credentials.
- Not recommended unless you control both networks and trust channel.

If you need remote DB integration, implement a small bridge on the client side that exposes a secure API for central pull (preferred over granting DB access directly).

4) Add several other clients at once
-----------------------------------
- Use automation (Ansible, Terraform, or simple scripts) to POST multiple registration requests.
- Example script (bash):
```bash
for org in "OrgA" "OrgB" "OrgC"; do
  curl -s -X POST http://localhost:5000/api/federated/register \
    -H "Content-Type: application/json" \
    -d "{\"organization\":\"${org}\",\"subnet\":\"10.0.0.0/8\",\"server_url\":\"https://${org}.local:5001\"}"
done
```

5) Dashboard: selecting clients
------------------------------
- The Zero-Day dashboard accepts a comma-separated `client_ids` query string to filter alerts.
- Example: `GET /zero-day/?client_ids=fc_A,fc_B` will show alerts only from those clients.
- The anomalies API also accepts `client_ids` to restrict results.

6) Security & best practices
----------------------------
- Always use HTTPS and validate TLS certificates.
- Store API keys securely on clients (do not hardcode in scripts).
- Limit access via firewall rules to only the required endpoints.
- Use VPN or tunnel for remote DB access if unavoidable.

7) Troubleshooting
------------------
- Check client heartbeat with: `GET /api/federated/clients/real-time`.
- Verify client shows as `online` and `last_heartbeat` is recent.
- If alerts don't appear, ensure forwarding component sends to `/api/v1/alerts` or client forwards to central ingest.

If you want, I can add a sample federated client script into `scripts/` and an example alert-forwarder service. Contact me which pattern you prefer (forwarding vs remote DB bridge).
