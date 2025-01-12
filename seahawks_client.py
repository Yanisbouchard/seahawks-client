import os
import json
import time
import uuid
import socket
import psutil
import threading
import requests
import logging
from datetime import datetime
from flask import Flask, jsonify, request

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('seahawks_client.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

class SeahawksClient:
    def __init__(self, server_url, name, location):
        self.server_url = server_url
        self.name = name
        self.location = location
        self.client_id = self.get_or_create_client_id()
        self.nm = psutil.net_if_addrs()
        self.running = True
        logging.info(f"Client initialisé avec: name={self.name}, location={self.location}")

    def get_or_create_client_id(self):
        """Récupère ou crée un ID unique pour ce client"""
        id_file = 'client_id.txt'
        if os.path.exists(id_file):
            with open(id_file, 'r') as f:
                return f.read().strip()
        
        client_id = str(uuid.uuid4().hex)
        with open(id_file, 'w') as f:
            f.write(client_id)
        return client_id
    
    def get_network_info(self):
        """Récupère les informations réseau"""
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        
        # Pour Linux, on peut utiliser ip route
        subnet = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            # On suppose un /24 pour le sous-réseau
            subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
        except:
            pass
                
        logging.info(f"Informations réseau détectées : IP={ip}, Subnet={subnet}")
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
            
        logging.info(f"Scan du réseau {network_info['subnet']}...")
        devices = []
        for interface_name, interface_addresses in self.nm.items():
            for address in interface_addresses:
                if str(address.family) == 'AddressFamily.AF_INET':
                    ip = address.address
                    if ip != network_info['ip']:
                        device = {
                            'ip': ip,
                            'hostname': 'Unknown',
                            'mac': 'Unknown',
                            'vendor': 'Unknown',
                            'status': 'up'
                        }
                        devices.append(device)
                        logging.info(f"Appareil trouvé : {device}")
        
        return devices
    
    def register_with_server(self):
        """Enregistre ce client auprès du serveur"""
        network_info = self.get_network_info()
        data = {
            'client_id': self.client_id,
            'name': self.name,
            'location': self.location,
            'hostname': network_info['hostname'],
            'ip': network_info['ip'],
            'subnet': network_info['subnet']
        }
        
        logging.info(f"Tentative d'enregistrement avec les données : {json.dumps(data, indent=2)}")
        try:
            response = requests.post(f"{self.server_url}/api/register", json=data)
            logging.info(f"Code de réponse : {response.status_code}")
            logging.info(f"Contenu de la réponse : {json.dumps(response.json(), indent=2)}\n")
            
            if response.status_code == 200:
                logging.info("Enregistrement réussi")
                return True
        except Exception as e:
            logging.error(f"Erreur lors de l'enregistrement : {str(e)}")
        return False
    
    def send_devices(self, devices):
        """Envoie la liste des appareils au serveur"""
        if not devices:
            return
            
        logging.info(f"Envoi de {len(devices)} appareils au serveur...")
        try:
            data = {
                'wan_id': self.client_id,
                'devices': devices
            }
            response = requests.post(f"{self.server_url}/api/devices/update", json=data)
            
            if response.status_code == 200:
                logging.info("Appareils mis à jour avec succès")
                return True
            else:
                logging.error(f"Erreur lors de l'envoi des appareils. Code : {response.status_code}")
        except Exception as e:
            logging.error(f"Erreur lors de l'envoi des appareils : {str(e)}")
        return False

    def ping_server(self):
        """Envoie un ping au serveur pour maintenir le statut online"""
        while self.running:
            try:
                self.register_with_server()
            except Exception as e:
                logging.error(f"Erreur lors du ping : {str(e)}")
            time.sleep(1)  # Ping toutes les secondes
    
    def start_monitoring(self, update_interval=60):
        """Démarre le monitoring en continu"""
        if self.register_with_server():
            logging.info(f"Client enregistre avec succes. ID: {self.client_id}")
            
            # Démarrer le thread de ping
            ping_thread = threading.Thread(target=self.ping_server)
            ping_thread.daemon = True
            ping_thread.start()
            
            # Boucle principale pour le scan réseau
            while self.running:
                try:
                    # Scan et envoi des appareils
                    devices = self.scan_network()
                    self.send_devices(devices)
                    
                    logging.info("\n")  # Ligne vide pour la lisibilité
                    time.sleep(update_interval)
                except KeyboardInterrupt:
                    logging.info("\nArrêt du monitoring...")
                    self.running = False
                    break
                except Exception as e:
                    logging.error(f"Erreur lors du monitoring : {str(e)}")
                    time.sleep(update_interval)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Seahawks Network Monitor Client')
    parser.add_argument('--server', required=True, help='URL du serveur (ex: http://localhost:5000)')
    parser.add_argument('--name', required=True, help='Nom du WAN')
    parser.add_argument('--location', required=True, help='Localisation du WAN')
    parser.add_argument('--interval', type=int, default=60, help='Intervalle de mise à jour en secondes')
    
    args = parser.parse_args()
    
    client = SeahawksClient(args.server, args.name, args.location)
    client.start_monitoring(args.interval)
