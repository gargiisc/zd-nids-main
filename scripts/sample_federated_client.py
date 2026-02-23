"""
Sample Federated Client
- Registers with central server
- Sends periodic heartbeats
- Forwards alerts (simulated)
- Demonstrates basic local 'train' and upload (stub)

Usage: python scripts/sample_federated_client.py --server http://localhost:5000
"""
import requests
import time
import argparse
import uuid
import random
import json
from datetime import datetime

class SampleFederatedClient:
    def __init__(self, server, organization, subnet, api_key=None, client_id=None):
        self.server = server.rstrip('/')
        self.organization = organization
        self.subnet = subnet
        self.api_key = api_key
        self.client_id = client_id
        self.headers = {'Content-Type': 'application/json'}
        if self.api_key:
            self.headers['X-API-Key'] = self.api_key

    def register(self):
        if self.client_id and self.api_key:
            print('Already registered:', self.client_id)
            return True
        payload = {
            'organization': self.organization,
            'subnet': self.subnet,
            'server_url': f'{self.server}/client/{self.organization}'
        }
        try:
            r = requests.post(f'{self.server}/api/federated/register', json=payload, timeout=10)
            r.raise_for_status()
            data = r.json()
            self.client_id = data.get('client_id')
            self.api_key = data.get('api_key')
            self.headers['X-API-Key'] = self.api_key
            print('Registered client:', self.client_id)
            return True
        except Exception as e:
            print('Registration failed:', e)
            return False

    def send_heartbeat(self, flows_processed=0, attacks_detected=0, model_version=1, local_accuracy=0.9):
        payload = {
            'client_id': self.client_id,
            'flows_processed': flows_processed,
            'attacks_detected': attacks_detected,
            'model_version': model_version,
            'local_accuracy': local_accuracy,
            'local_precision': 0.9,
            'local_recall': 0.85
        }
        try:
            r = requests.post(f'{self.server}/api/federated/heartbeat', json=payload, headers=self.headers, timeout=6)
            if r.status_code == 200:
                print(f'Heartbeat sent: flows={flows_processed} attacks={attacks_detected}')
                return True
            else:
                print('Heartbeat response:', r.status_code, r.text[:200])
        except Exception as e:
            print('Heartbeat failed:', e)
        return False

    def forward_alert(self, source_ip, dest_ip, src_port=1234, dst_port=80, attack_type='Malware'):
        # This demonstrates forwarding a minimal alert to central ingest API
        alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'protocol': 'TCP',
            'attack_type': attack_type,
            'severity': 'high',
            'confidence': round(random.uniform(0.6, 0.99), 2),
            'risk_score': round(random.uniform(0.6, 0.99), 2),
            'model_used': 'local-xgb',
            'fed_client_id': self.client_id
        }
        try:
            r = requests.post(f'{self.server}/api/v1/alerts', json={'alerts':[alert]}, headers=self.headers, timeout=8)
            print('Forwarded alert:', r.status_code)
        except Exception as e:
            print('Forwarding failed:', e)

    def local_train_and_upload(self):
        # Placeholder for local training. In a real client, train local model and upload gradients/weights
        print('Performing local training (stub) ...')
        time.sleep(2 + random.random()*2)
        # Simulate uploading model update
        update_payload = {
            'client_id': self.client_id,
            'model_version': str(uuid.uuid4()),
            'num_samples': random.randint(100, 1000),
            'metrics': {'local_accuracy': round(random.uniform(0.7, 0.95), 3)}
        }
        try:
            r = requests.post(f'{self.server}/api/federated/upload-update', json=update_payload, headers=self.headers, timeout=8)
            print('Uploaded update, status:', r.status_code)
        except Exception as e:
            print('Upload failed (endpoint may not exist in test env):', e)

    def run(self, heartbeat_interval=30):
        flows = 0
        attacks = 0
        while True:
            flows += random.randint(50, 200)
            if random.random() < 0.02:
                attacks += 1
                # forward a simulated alert
                self.forward_alert(f'192.168.{random.randint(1,254)}.{random.randint(2,250)}', '10.0.0.5', src_port=random.randint(1000,65000), dst_port=443, attack_type=random.choice(['Malware','DDoS','SQL Injection']))
            self.send_heartbeat(flows_processed=flows, attacks_detected=attacks, model_version=1, local_accuracy=round(0.85+random.random()*0.1,3))
            # occasionally train
            if random.random() < 0.1:
                self.local_train_and_upload()
            time.sleep(heartbeat_interval)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--server', default='http://localhost:5000')
    p.add_argument('--org', default='DemoOrg')
    p.add_argument('--subnet', default='192.168.100.0/24')
    p.add_argument('--interval', type=int, default=30)
    args = p.parse_args()

    client = SampleFederatedClient(args.server, args.org, args.subnet)
    if client.register():
        try:
            client.run(heartbeat_interval=args.interval)
        except KeyboardInterrupt:
            print('Client stopped')
