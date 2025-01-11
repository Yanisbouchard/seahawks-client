import os
import json
import time
import uuid
import socket
import psutil
import threading
import requests
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)

class NetworkMonitor:
    def __init__(self, server_url, scan_interval=30):
        self.server_url = server_url
        self.scan_interval = scan_interval
        self.client_id = str(uuid.uuid4())
        self.hostname = socket.gethostname()
        self.ip = self._get_ip()
        self.subnet = self._get_subnet()
        self.location = os.getenv('LOCATION', 'Non spécifié')
        self.devices = []
        self.running = False

    def _get_ip(self):
        """Récupère l'adresse IP du client"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # On se connecte à un DNS Google (ne fait pas vraiment de connexion)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            print(f"Erreur lors de la récupération de l'IP: {str(e)}")
            return socket.gethostbyname(socket.gethostname())

    def _get_subnet(self):
        """Récupère le sous-réseau"""
        try:
            ip = self._get_ip()
            # On suppose un masque /24 pour simplifier
            return '.'.join(ip.split('.')[:3]) + '.0/24'
        except Exception as e:
            print(f"Erreur lors de la récupération du masque: {str(e)}")
            return None

    def scan_network(self):
        """Scan le réseau pour trouver les appareils"""
        devices = []
        try:
            # Scan des connexions actives
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                    except:
                        hostname = conn.raddr.ip
                    
                    devices.append({
                        'ip': conn.raddr.ip,
                        'hostname': hostname,
                        'status': 'up'
                    })
            self.devices = devices
        except Exception as e:
            print(f"Erreur lors du scan réseau: {str(e)}")

    def register(self):
        """Enregistre le client auprès du serveur"""
        try:
            data = {
                'client_id': self.client_id,
                'name': self.hostname,
                'ip': self.ip,
                'subnet': self.subnet,
                'location': self.location
            }
            response = requests.post(f"{self.server_url}/api/register", json=data)
            return response.status_code == 200
        except Exception as e:
            print(f"Erreur lors de l'enregistrement: {str(e)}")
            return False

    def update_devices(self):
        """Met à jour la liste des appareils sur le serveur"""
        try:
            data = {
                'wan_id': self.client_id,
                'devices': self.devices
            }
            response = requests.post(f"{self.server_url}/api/devices/update", json=data)
            return response.status_code == 200
        except Exception as e:
            print(f"Erreur lors de la mise à jour des appareils: {str(e)}")
            return False

    def start_monitoring(self):
        """Démarre le monitoring"""
        self.running = True
        while self.running:
            self.scan_network()
            self.update_devices()
            time.sleep(self.scan_interval)

    def stop_monitoring(self):
        """Arrête le monitoring"""
        self.running = False

# Routes API
@app.route('/api/scan', methods=['POST'])
def force_scan():
    """Force un scan réseau"""
    monitor.scan_network()
    return jsonify({'success': True})

if __name__ == '__main__':
    # Récupération de l'URL du serveur depuis les variables d'environnement
    server_url = os.getenv('SERVER_URL', 'http://localhost:5000')
    
    # Création du moniteur réseau
    monitor = NetworkMonitor(server_url)
    
    # Enregistrement auprès du serveur
    if not monitor.register():
        print("Erreur lors de l'enregistrement auprès du serveur")
        exit(1)
    
    # Démarrage du thread de monitoring
    monitor_thread = threading.Thread(target=monitor.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # Démarrage du serveur Flask
    app.run(host='0.0.0.0', port=5000)
