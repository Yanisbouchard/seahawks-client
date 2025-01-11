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
    def __init__(self, server_url, name, location):
        self.server_url = server_url
        self.name = name
        self.location = location
        self.client_id = None  # Sera défini lors de l'enregistrement
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
        
        # Créer une connexion temporaire pour obtenir l'IP réelle
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(('8.8.8.8', 80))
            ip = temp_socket.getsockname()[0]
            temp_socket.close()
        except:
            # Fallback sur l'IP hostname si la connexion échoue
            ip = socket.gethostbyname(hostname)
        
        # Calculer le sous-réseau
        subnet = f"{'.'.join(ip.split('.')[:3])}.0/24"
        
        print(f"Informations réseau détectées : IP={ip}, Subnet={subnet}")
                
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
            
        print(f"Scan du réseau {network_info['subnet']}...")
        
        try:
            # Arguments nmap : -sn = ping scan, -n = no DNS resolution
            self.nm.scan(hosts=network_info['subnet'], arguments='-sn -n')
            
            devices = []
            for host in self.nm.all_hosts():
                try:
                    device = {
                        'ip': host,
                        'hostname': self.nm[host].hostname() or 'Unknown',
                        'mac': self.nm[host]['addresses'].get('mac', 'Unknown'),
                        'vendor': self.nm[host]['vendor'].get(self.nm[host]['addresses'].get('mac', ''), 'Unknown'),
                        'status': 'up' if self.nm[host]['status']['state'] == 'up' else 'down'
                    }
                    print(f"Appareil trouvé : {device}")
                    devices.append(device)
                except Exception as e:
                    print(f"Erreur lors du traitement de l'hôte {host}: {str(e)}")
            
            # Envoyer les appareils au serveur
            if devices:
                print(f"Envoi de {len(devices)} appareils au serveur...")
                self.send_devices_to_server(devices)
            
            return devices
        except Exception as e:
            print(f"Erreur lors du scan réseau: {str(e)}")
            return []
    
    def check_latency(self):
        """Vérifie la latence vers Google DNS"""
        try:
            latency = ping('8.8.8.8', timeout=2)
            if latency is not None:
                return round(latency * 1000, 2)  # Conversion en ms
            return None
        except Exception:
            return None
    
    def register_with_server(self):
        """Enregistre le client avec le serveur"""
        network_info = self.get_network_info()
        
        # Générer un ID unique basé sur l'adresse MAC et l'hostname
        mac = self.get_mac_address()
        self.client_id = f"{mac}_{network_info['hostname']}"
        
        data = {
            'client_id': self.client_id,
            'name': self.name,
            'location': self.location,
            'hostname': network_info['hostname'],
            'ip': network_info['ip'],
            'subnet': network_info['subnet']
        }
        
        print(f"Tentative d'enregistrement avec les données : {data}")
        
        try:
            response = requests.post(f"{self.server_url}/api/register", json=data)
            print(f"Code de réponse : {response.status_code}")
            print(f"Contenu de la réponse : {response.text}")
            
            if response.status_code == 200:
                print("Enregistrement réussi")
                return True
            else:
                print("Echec de l'enregistrement du client")
                return False
        except Exception as e:
            print(f"Erreur lors de l'enregistrement : {str(e)}")
            return False
            
    def get_mac_address(self):
        """Récupère l'adresse MAC de l'interface principale"""
        try:
            # Obtenir l'interface principale
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(('8.8.8.8', 80))
            interface = psutil.net_if_addrs()[temp_socket.getsockname()[0]]
            temp_socket.close()
            
            # Trouver l'adresse MAC
            for addr in interface:
                if addr.family == psutil.AF_LINK:
                    return addr.address.replace(':', '')
        except:
            # Fallback : utiliser une adresse MAC aléatoire
            import uuid
            return uuid.uuid4().hex[:12]
    
    def send_devices_to_server(self, devices):
        """Envoie la liste des appareils au serveur"""
        if not self.client_id:
            print("Client non enregistré, impossible d'envoyer les appareils")
            return False
            
        data = {
            'client_id': self.client_id,
            'devices': devices
        }
        
        try:
            response = requests.post(f"{self.server_url}/api/devices/update", json=data)
            if response.status_code == 200:
                print("Appareils envoyés avec succès")
                return True
            else:
                print(f"Erreur lors de l'envoi des appareils. Code : {response.status_code}")
                return False
        except Exception as e:
            print(f"Erreur lors de l'envoi des appareils : {str(e)}")
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
    
    client = SeahawksClient(args.server, args.name, args.location)
    if client.register_with_server():
        print(f"Client enregistre avec succes. ID: {client.client_id}")
        client.start_monitoring()
    else:
        print("Echec de l'enregistrement du client")
