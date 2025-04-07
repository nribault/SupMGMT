# SupMGMT - Script de Configuration de Supervision Windows

## Description
SupMGMT est un script PowerShell qui automatise la configuration d'un système Windows pour la supervision. Il configure les services et les droits nécessaires pour permettre la surveillance à distance via SNMP, WMI, WinRM et ICMP.

## Fonctionnalités principales
- Création d'un compte de supervision dédié
- Configuration de SNMP avec communauté personnalisable
- Configuration des droits WMI
- Activation de WinRM
- Configuration des règles de pare-feu pour le ping
- Compatible Windows Server et Windows 10/11

## Prérequis
- PowerShell 5.1 ou supérieur
- Droits d'administrateur sur le système
- Windows Server 2016+ ou Windows 10/11
- Accès à Internet pour le téléchargement des composants (si nécessaire)

## Installation
1. Téléchargez le script `SupMGMT.ps1`
2. Ouvrez une console PowerShell en tant qu'administrateur
3. Exécutez le script :
```powershell
.\SupMGMT.ps1
```

## Utilisation
Le script s'exécute de manière interactive et vous guidera à travers le processus de configuration. Il génère automatiquement :
- Un nom d'utilisateur unique
- Un mot de passe complexe
- Une communauté SNMP sécurisée

## Fonctionnalités détaillées

### Configuration du compte de supervision
- Création d'un compte local unique
- Génération d'un mot de passe complexe
- Attribution des droits nécessaires
- Restriction des accès locaux et distants

### Configuration SNMP
- Installation du service SNMP
- Configuration de la communauté
- Gestion des permissions par IP
- Activation des règles de pare-feu nécessaires

### Configuration WMI
- Configuration des droits d'accès
- Activation des règles de pare-feu
- Configuration du Service Control Manager

### Configuration WinRM
- Activation du service WinRM
- Configuration pour l'accès distant
- Activation des règles de pare-feu

### Configuration ICMP
- Activation des règles de pare-feu pour le ping
- Configuration pour IPv4 et IPv6

## Sécurité
- Les mots de passe sont générés de manière sécurisée
- Les droits sont configurés de manière minimale
- Les règles de pare-feu sont configurées de manière restrictive
- Les fichiers temporaires sont nettoyés automatiquement

## Dépannage
En cas d'erreur, le script fournit des messages détaillés. Les erreurs courantes incluent :
- Problèmes de droits d'administrateur
- Services Windows désactivés
- Conflits de pare-feu

## Contribution
Les contributions sont les bienvenues. Pour contribuer :
1. Fork le projet
2. Créez une branche pour votre fonctionnalité
3. Committez vos changements
4. Poussez vers la branche
5. Créez une Pull Request

## Licence
Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

## Auteurs
- Nicolas RIBAULT / OOPAYA SAS
