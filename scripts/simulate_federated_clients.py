#!/usr/bin/env python3
"""
Federated Client Simulator
==========================
Simulates federated clients sending status updates to the dashboard
for testing real-time SSE updates.

Usage:
    python scripts/simulate_federated_clients.py
"""

import requests
import json
import time
import random
from datetime import datetime
import argparse

# Configuration
API_BASE_URL = "http://localhost:5000"
CLIENTS = [
    {
        "id": "fed-hospital-001",
        "organization": "Hospital A",
        "subnet": "192.168.1.0/24"
    },
    {
        "id": "fed-bank-001",
        "organization": "Bank B",
        "subnet": "10.0.1.0/24"
    },
    {
        "id": "fed-university-001",
        "organization": "University C",
        "subnet": "172.16.0.0/16"
    },
    {
        "id": "fed-telecom-001",
        "organization": "Telecom D",
        "subnet": "203.0.113.0/24"
    },
    {
        "id": "fed-research-001",
        "organization": "Research Institute E",
        "subnet": "198.51.100.0/24"
    }
]

STATUSES = ["online", "offline", "training"]


def register_client(client_info):
    """Register a new federated client directly in database."""
    try:
        # Import Flask app context to register clients
        import sys
        from pathlib import Path
        
        # Add project root to path
        project_root = Path(__file__).parent.parent
        sys.path.insert(0, str(project_root))
        
        from app import create_app, db
        from app.models.database import FederatedClient
        
        app = create_app()
        
        with app.app_context():
            # Check if client already exists
            existing = FederatedClient.query.filter_by(
                organization=client_info["organization"]
            ).first()
            
            if existing:
                print(f"✓ Client already registered {client_info['organization']}: {existing.client_id}")
                return existing.client_id
            
            # Create new client
            import uuid
            client_id = f"fed-{client_info['organization'].lower().replace(' ', '-')}-{str(uuid.uuid4())[:8]}"
            
            new_client = FederatedClient(
                client_id=client_id,
                organization=client_info["organization"],
                subnet=client_info["subnet"],
                server_url=f"http://{client_info['organization'].lower().replace(' ', '-')}:8001",
                api_key=f"key_{str(uuid.uuid4())[:16]}",
                is_active=True,
                client_metadata='{"version": "1.0", "device": "network_tap"}'
            )
            
            db.session.add(new_client)
            db.session.commit()
            
            print(f"✓ Registered {client_info['organization']}: {client_id}")
            return client_id
    
    except Exception as e:
        print(f"✗ Error registering client: {e}")
        import traceback
        traceback.print_exc()
        return None


def send_status_update(client_id, organization, status):
    """Send a status update for a client."""
    url = f"{API_BASE_URL}/api/federated-clients/update-status"
    
    # Generate realistic metrics
    if status == "training":
        accuracy = random.uniform(0.85, 0.98)
        loss = random.uniform(0.02, 0.15)
        training_round = random.randint(1, 100)
    else:
        accuracy = random.uniform(0.80, 0.95)
        loss = random.uniform(0.05, 0.20)
        training_round = random.randint(0, 100)
    
    payload = {
        "client_id": client_id,
        "status": status,
        "training_round": training_round,
        "model_accuracy": accuracy,
        "model_loss": loss,
        "flows_processed": random.randint(1000, 100000),
        "attacks_detected": random.randint(0, 50)
    }
    
    try:
        resp = requests.post(url, json=payload)
        if resp.status_code == 200:
            print(f"  ✓ {organization} ({status}): Acc={accuracy:.2%}, Round={training_round}")
            return True
        else:
            print(f"  ✗ Failed to update {organization}: {resp.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Error updating status: {e}")
        return False


def simulate_clients(duration=300, interval=10):
    """Simulate multiple federated clients sending updates."""
    print("\n" + "="*60)
    print("Federated Client Simulator")
    print("="*60)
    print(f"API Base URL: {API_BASE_URL}")
    print(f"Simulation Duration: {duration}s")
    print(f"Update Interval: {interval}s")
    print("="*60 + "\n")
    
    # Register clients
    print("Registering clients...\n")
    registered_clients = {}
    for client_info in CLIENTS:
        client_id = register_client(client_info)
        if client_id:
            registered_clients[client_id] = client_info["organization"]
        time.sleep(0.5)
    
    if not registered_clients:
        print("\n✗ No clients registered. Exiting.")
        return
    
    print(f"\n✓ Successfully registered {len(registered_clients)} clients\n")
    print("Starting simulation...\n")
    
    # Simulate updates
    start_time = time.time()
    update_count = 0
    
    try:
        while time.time() - start_time < duration:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Update #{update_count + 1}")
            
            for client_id, organization in registered_clients.items():
                status = random.choice(STATUSES)
                send_status_update(client_id, organization, status)
            
            update_count += 1
            elapsed = time.time() - start_time
            remaining = duration - elapsed
            
            if remaining > 0:
                print(f"\nNext update in {interval}s (remaining: {remaining:.0f}s)")
                time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\n✓ Simulation stopped by user")
    
    print("\n" + "="*60)
    print(f"Simulation Complete")
    print(f"Total Updates: {update_count}")
    print(f"Clients Simulated: {len(registered_clients)}")
    print("="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Simulate federated clients")
    parser.add_argument('--url', default='http://localhost:5000', help='API base URL')
    parser.add_argument('--duration', type=int, default=300, help='Simulation duration in seconds')
    parser.add_argument('--interval', type=int, default=10, help='Update interval in seconds')
    
    args = parser.parse_args()
    
    global API_BASE_URL
    API_BASE_URL = args.url
    
    simulate_clients(duration=args.duration, interval=args.interval)


if __name__ == '__main__':
    main()
