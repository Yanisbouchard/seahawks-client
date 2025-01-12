import os
import json
import time
import uuid
import socket
import psutil
import threading
import requests
import logging
import argparse
from datetime import datetime
from flask import Flask, jsonify, request
import ping3
import nmap
import concurrent.futures

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
        self.client_id = str(uuid.uuid4())
        self.running = True
        self.nm = nmap.PortScanner()
        
        logging.info(f"Client initialisé avec: name={name}, location={location}")
        
    def get_network_latency(self):
        """Mesure la latence réseau vers 8.8.8.8"""
        try:
            latencies = []
            for _ in range(3):  # Fait 3 pings et prend la moyenne
                delay = ping3.ping('8.8.8.8')
                if delay is not None:
                    latencies.append(delay * 1000)  # Convertit en ms
            
            if latencies:
                avg_latency = sum(latencies) / len(latencies)
                return avg_latency
            return None
        except Exception as e:
            logging.error(f"Erreur lors du ping : {str(e)}")
            return None

    def scan_ports(self, ip, ports='1-1024'):
        """Scanne les ports d'une IP"""
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, ports, arguments='-sT -T4')
            open_ports = []
            
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    ports = nm[ip][proto].keys()
                    for port in ports:
                        state = nm[ip][proto][port]['state']
                        if state == 'open':
                            service = nm[ip][proto][port].get('name', 'unknown')
                            port_info = {
                                'port': int(port),
                                'service': service
                            }
                            open_ports.append(port_info)
                            logging.info(f"Port trouvé sur {ip}: {port_info}")
            
            if not open_ports:
                logging.info(f"Aucun port ouvert trouvé pour {ip}")
            return open_ports
            
        except nmap.PortScannerError as e:
            logging.error(f"Erreur nmap lors du scan des ports de {ip}: {str(e)}")
            return []
        except Exception as e:
            logging.error(f"Erreur inattendue lors du scan des ports de {ip}: {str(e)}")
            return []

    def scan_network(self):
        """Scanne le réseau pour trouver les appareils"""
        network_info = self.get_network_info()
        if not network_info['subnet']:
            return []
            
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network_info['subnet'], arguments='-sn')
            devices = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_ip = {}
                for host in nm.all_hosts():
                    if 'mac' in nm[host]['addresses']:
                        device = {
                            'ip': host,
                            'mac': nm[host]['addresses']['mac'],
                            'hostname': nm[host].hostname() or 'Unknown'
                        }
                        future_to_ip[executor.submit(self.scan_ports, host)] = device
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    device = future_to_ip[future]
                    device['open_ports'] = future.result()
                    devices.append(device)
                    logging.info(f"Appareil trouvé : {device}")
            
            return devices
        except Exception as e:
            logging.error(f"Erreur lors du scan réseau : {str(e)}")
            return []

    def get_system_load(self):
        """Récupère la charge CPU"""
        try:
            return psutil.cpu_percent(interval=1)
        except Exception as e:
            logging.error(f"Erreur lors de la récupération de la charge CPU : {str(e)}")
            return None

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
    
    def update_devices(self):
        """Met à jour la liste des appareils"""
        devices = self.scan_network()
        latency = self.get_network_latency()
        cpu_load = self.get_system_load()
        
        data = {
            'client_id': self.client_id,
            'devices': devices,
            'network_stats': {
                'latency': latency,
                'cpu_load': cpu_load
            }
        }
        
        try:
            response = requests.post(f"{self.server_url}/api/devices/update", json=data)
            if response.status_code == 200:
                logging.info("Mise à jour des appareils réussie")
            else:
                logging.error(f"Erreur lors de la mise à jour des appareils. Code : {response.status_code}")
                logging.error(f"Réponse du serveur : {response.text}")
        except Exception as e:
            logging.error(f"Erreur lors de la mise à jour des appareils : {str(e)}")

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
        
        # Assure-toi que l'URL se termine par /api/register
        api_url = self.server_url.rstrip('/') + '/api/register'
        logging.info(f"URL d'enregistrement : {api_url}")
        logging.info(f"Tentative d'enregistrement avec les données : {json.dumps(data, indent=2)}")
        
        try:
            response = requests.post(api_url, json=data)
            logging.info(f"Code de réponse : {response.status_code}")
            
            try:
                response_json = response.json()
                logging.info(f"Contenu de la réponse : {json.dumps(response_json, indent=2)}\n")
            except ValueError:
                logging.error(f"La réponse n'est pas du JSON valide : {response.text}")
            
            if response.status_code == 200:
                logging.info("Enregistrement réussi")
                return True
            elif response.status_code == 404:
                logging.error("URL d'enregistrement non trouvée. Vérifiez l'URL du serveur.")
                logging.error("L'URL doit être de la forme : http://ip:port")
            else:
                logging.error(f"Erreur lors de l'enregistrement. Code : {response.status_code}")
                logging.error(f"Réponse du serveur : {response.text}")
        except requests.exceptions.ConnectionError:
            logging.error(f"Impossible de se connecter au serveur {api_url}")
            logging.error("Vérifiez que le serveur est démarré et accessible")
        except Exception as e:
            logging.error(f"Erreur lors de l'enregistrement : {str(e)}")
        return False
    
    def ping_server(self):
        """Envoie un ping au serveur pour maintenir le statut online"""
        while self.running:
            try:
                self.register_with_server()
            except Exception as e:
                logging.error(f"Erreur lors du ping : {str(e)}")
            time.sleep(1)  # Ping toutes les secondes
    
    def start(self, update_interval=30):
        """Démarre le client"""
        if not self.register_with_server():
            logging.error("Impossible de s'enregistrer auprès du serveur")
            return
            
        # Démarre le thread de ping
        ping_thread = threading.Thread(target=self.ping_server)
        ping_thread.daemon = True
        ping_thread.start()
        
        # Boucle principale
        try:
            while self.running:
                try:
                    # Scan et envoi des appareils
                    self.update_devices()
                    
                    logging.info("\n")  # Ligne vide pour la lisibilité
                    time.sleep(update_interval)
                    
                except Exception as e:
                    logging.error(f"Erreur dans la boucle principale : {str(e)}")
                    time.sleep(5)  # Attend avant de réessayer
                    
        except KeyboardInterrupt:
            logging.info("Arrêt du client...")
            self.running = False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Seahawks Network Monitor Client')
    parser.add_argument('--server', required=True, help='URL du serveur (ex: http://localhost:5000)')
    parser.add_argument('--name', required=True, help='Nom du WAN')
    parser.add_argument('--location', required=True, help='Localisation du WAN')
    parser.add_argument('--interval', type=int, default=30, help='Intervalle de mise à jour en secondes')
    
    args = parser.parse_args()
    
    client = SeahawksClient(args.server, args.name, args.location)
    client.start(args.interval)
