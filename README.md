# Seahawks Client

## Version 3.0.0

Client de monitoring réseau pour l'application Seahawks. Ce client permet de :
- Scanner automatiquement le réseau local
- Détecter les appareils connectés
- Envoyer les informations au serveur Seahawks
- Surveiller la latence et l'état de la connexion

## Installation

1. Cloner le dépôt :
```bash
git clone https://github.com/votre-repo/seahawks-client.git
cd seahawks-client
```

2. Installer les dépendances :
```bash
pip install -r requirements.txt
```

## Configuration

1. Modifier le fichier `config.json` avec l'adresse de votre serveur :
```json
{
    "server_url": "http://votre-serveur:5000"
}
```

## Utilisation

1. Lancer le client :
```bash
python seahawks_client.py
```

Le client va :
1. S'enregistrer auprès du serveur
2. Scanner le réseau local
3. Envoyer les informations des appareils détectés
4. Continuer à monitorer le réseau

## Nouveautés de la version 3.0.0

- Amélioration de la détection des appareils
- Réenregistrement automatique si le WAN n'est pas trouvé
- Meilleure gestion des erreurs
- Support des réseaux externes
- Optimisation des performances

## Dépendances

- Python 3.8+
- Voir `requirements.txt` pour la liste complète
