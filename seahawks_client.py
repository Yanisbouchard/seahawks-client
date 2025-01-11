import os
import json
import socket
import uuid
import requests
import time
import nmap
import psutil
from ping3 import ping
from datetime import datetime

class SeahawksClient:
    def __init__(self, server_url):
        self.server_url = server_url
        self.client_id = self.get_or_create_client_id()
        self.nm = nmap.PortScanner()
        
    def get_or_create_client_id(self):
        """Récupère ou crée un ID unique pour ce client"""
        id_file = 'client_id.txt'
        if os.path.exists(id_file):
            with open(id_file, 'r') as f:
                return f.read().strip()
        
        client_id = str(uuid.uuid4())
        with open(id_file, 'w') as f:
            f.write(client_id)
        return client_id
    
    def get_network_info(self):
        """Récupère les informations réseau"""
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        
        # Trouver le sous-réseau
        network_interfaces = psutil.net_if_addrs()
        subnet = None
        for interface, addrs in network_interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == ip:
                    subnet = f"{'.'.join(ip.split('.')[:3])}.0/24"
                    break
            if subnet:
                break
                
        return {
            'hostname': hostname,
            'ip': ip,
            'subnet': subnet
        }
    
    def scan_network(self):
        """Scan le réseau local"""
        network_info = self.get_network_info()
        if not network_info['subnet']:
            return []
            
        self.nm.scan(hosts=network_info['subnet'], arguments='-sn')
        
        devices = []
        for host in self.nm.all_hosts():
            if 'mac' in self.nm[host]['addresses']:
                device = {
                    'ip': host,
                    'hostname': self.nm[host].hostname(),
                    'mac': self.nm[host]['addresses']['mac'],
                    'vendor': self.nm[host]['vendor'].get(self.nm[host]['addresses']['mac'], 'Unknown'),
                    'status': 'up' if self.nm[host]['status']['state'] == 'up' else 'down'
                }
                devices.append(device)
        
        return devices
    
    def check_latency(self):
        """Vérifie la latence vers Google DNS"""
        try:
            latency = ping('8.8.8.8', timeout=2)
            if latency is not None:
                return round(latency * 1000, 2)  # Conversion en ms
            return None
        except Exception:
            return None
    
    def register_with_server(self, name, location):
        """Enregistre ce client auprès du serveur"""
        network_info = self.get_network_info()
        data = {
            'client_id': self.client_id,
            'name': name,
            'location': location,
            'hostname': network_info['hostname'],
            'ip': network_info['ip'],
            'subnet': network_info['subnet']
        }
        
        try:
            response = requests.post(f"{self.server_url}/api/register", json=data)
            return response.status_code == 200
        except Exception as e:
            print(f"Erreur lors de l'enregistrement: {str(e)}")
            return False
    
    def send_update(self):
        """Envoie une mise à jour au serveur"""
        data = {
            'client_id': self.client_id,
            'timestamp': datetime.now().isoformat(),
            'latency': self.check_latency(),
            'devices': self.scan_network()
        }
        
        try:
            response = requests.post(f"{self.server_url}/api/update", json=data)
            return response.status_code == 200
        except Exception as e:
            print(f"Erreur lors de la mise à jour: {str(e)}")
            return False
    
    def start_monitoring(self, update_interval=60):
        """Démarre le monitoring en continu"""
        while True:
            self.send_update()
            time.sleep(update_interval)

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Seahawks Network Monitor Client')
    parser.add_argument('--server', required=True, help='URL du serveur (ex: http://localhost:5000)')
    parser.add_argument('--name', required=True, help='Nom du WAN')
    parser.add_argument('--location', required=True, help='Localisation du WAN')
    
    args = parser.parse_args()
    
    client = SeahawksClient(args.server)
    if client.register_with_server(args.name, args.location):
        print(f"Client enregistre avec succes. ID: {client.client_id}")
        client.start_monitoring()
    else:
        print("Echec de l'enregistrement du client")
