# Seahawks Network Monitor - Client

Client de monitoring réseau pour Seahawks Network Monitor.

## Prérequis

1. Python 3.x
2. nmap installé sur le système
3. Les dépendances Python listées dans requirements.txt

## Installation

### Sur Debian/Ubuntu :
```bash
# Installation de Python et pip
apt install python3-pip

# Installation de nmap
apt install nmap

# Installation des dépendances Python
pip3 install -r requirements.txt
```

### Sur Windows :
1. Installer Python depuis [python.org](https://www.python.org/downloads/)
2. Installer nmap depuis [nmap.org](https://nmap.org/download.html)
3. Installer les dépendances :
```bash
pip install -r requirements.txt
```

## Utilisation

```bash
python3 seahawks_client.py --server http://IP_DU_SERVEUR:5000 --name "Nom du WAN" --location "Localisation"
```

Le client va :
1. S'enregistrer auprès du serveur
2. Scanner le réseau local pour détecter les appareils
3. Mesurer la latence vers 8.8.8.8
4. Envoyer ces informations au serveur toutes les minutes

## Configuration

Le client stocke son ID unique dans un fichier `client_id.txt`. Ce fichier est créé automatiquement lors du premier démarrage.
