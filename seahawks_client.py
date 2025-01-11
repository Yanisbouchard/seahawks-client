import os
import sys
import json
import time
import socket
import hashlib
import requests
import argparse
import threading
from datetime import datetime
from scapy.all import ARP, Ether, srp
import uuid
import nmap
import psutil
from ping3 import ping
from flask import jsonify, request

class SeahawksClient:
    def __init__(self, server_url, name, location):
        """Initialise le client Seahawks"""
        self.server_url = server_url
        self.name = name
        self.location = location
        self.client_id = None
        self.nm = nmap.PortScanner()
        self.app = Flask(__name__)
        
        # Ajout des routes
        self.app.add_url_rule('/api/scan', view_func=self.force_scan, methods=['POST'])
        self.app.add_url_rule('/api/scan_ports', view_func=self.scan_ports_endpoint, methods=['POST'])
        
    def get_or_create_client_id(self):
        """Récupère ou crée un ID unique pour ce client"""
        try:
            # Utiliser l'adresse IP comme identifiant unique
            ip = socket.gethostbyname(socket.gethostname())
            # Créer un hash unique basé sur l'IP
            client_id = hashlib.md5(ip.encode()).hexdigest()
            return client_id
        except Exception as e:
            print(f"Erreur lors de la création de l'ID client: {str(e)}")
            return None
    
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
        self.client_id = self.get_or_create_client_id()
        
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
            response = requests.post(f"{self.server_url}/api/wans/{self.client_id}/devices", json=data)
            if response.status_code == 404:
                # Si le WAN n'est pas trouvé, on le réenregistre
                self.register_with_server()
                # On réessaie d'envoyer les appareils
                response = requests.post(f"{self.server_url}/api/wans/{self.client_id}/devices", json=data)
                
            if not response.ok:
                print(f"Erreur lors de l'envoi des appareils. Code : {response.status_code}")
                return False
                
            print("Appareils envoyés avec succès")
            return True
        except Exception as e:
            print(f"Erreur lors de l'envoi des appareils : {str(e)}")
            return False
    
    def send_update(self):
        """Envoie une mise à jour au serveur"""
        try:
            # Scan du réseau
            devices = self.scan_network()
            
            # Préparer les données
            data = {
                'client_id': self.client_id,
                'timestamp': datetime.now().isoformat(),
                'latency': self.check_latency(),
                'devices': devices
            }
            
            # Envoyer les appareils
            devices_response = requests.post(f"{self.server_url}/api/wans/{self.client_id}/devices", json=data)
            if devices_response.status_code == 404:
                # Si le WAN n'est pas trouvé, on le réenregistre
                self.register_with_server()
                # On réessaie d'envoyer les appareils
                devices_response = requests.post(f"{self.server_url}/api/wans/{self.client_id}/devices", json=data)
                
            if not devices_response.ok:
                print(f"Erreur lors de l'envoi des appareils. Code : {devices_response.status_code}")
                return False
                
            return True
        except Exception as e:
            print(f"Erreur lors de l'envoi de la mise à jour: {str(e)}")
            return False
    
    def start_monitoring(self, update_interval=60):
        """Démarre le monitoring en continu"""
        while True:
            self.send_update()
            time.sleep(update_interval)
    
    def scan_ports(self, ip):
        """Scan les ports d'une IP spécifique"""
        try:
            # Scan des ports communs
            self.nm.scan(ip, arguments='-sS -F')
            
            ports = []
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    ports_list = sorted(self.nm[ip][proto].keys())
                    for port in ports_list:
                        state = self.nm[ip][proto][port]['state']
                        service = self.nm[ip][proto][port].get('name', '')
                        ports.append({
                            'port': port,
                            'protocol': proto,
                            'state': state,
                            'service': service
                        })
            return ports
        except Exception as e:
            print(f"Erreur lors du scan des ports: {str(e)}")
            return []
            
    def force_scan(self):
        """Force un scan réseau"""
        try:
            devices = self.scan_network()
            return jsonify({'success': True, 'devices': devices})
        except Exception as e:
            print(f"Erreur lors du scan: {str(e)}")
            return jsonify({'error': str(e)}), 500
            
    def scan_ports_endpoint(self):
        """Endpoint pour scanner les ports d'une IP"""
        try:
            ip = request.json.get('ip')
            if not ip:
                return jsonify({'error': 'IP manquante'}), 400
                
            ports = self.scan_ports(ip)
            return jsonify({'success': True, 'ports': ports})
        except Exception as e:
            print(f"Erreur lors du scan des ports: {str(e)}")
            return jsonify({'error': str(e)}), 500

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
    client.app.run(debug=True)
