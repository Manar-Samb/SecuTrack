# SecuTrack

**SecuTrack** est une plateforme web sécurisée dédiée à la gestion des projets étudiants dans un cadre académique. Elle offre un espace sécurisé pour le dépôt, le suivi, la validation et l’audit des projets soumis par les étudiants, tout en garantissant la confidentialité, l’intégrité et la traçabilité des données.

##  Objectifs

- Créer un portail sécurisé pour les étudiants, enseignants et administrateurs pédagogiques.
- Assurer la protection des fichiers et métadonnées soumis.
- Gérer les droits d’accès selon les rôles.
- Fournir un historique clair et horodaté des actions.
- Appliquer les principes DevSecOps dès la conception.

##  Technologies utilisées

- **Front-end** : HTML, CSS, JavaScript (Bootstrap si nécessaire)
- **Back-end** : Python (Flask)
- **Base de données** : MySQL
- **Sécurité** :
  - Authentification par mot de passe haché (`werkzeug.security`)
  - Chiffrement des fichiers (`PyCryptodome`)
  - Journalisation des actions (logs base de données ou fichiers)

##  Fonctionnalités principales

- Connexion sécurisée avec session protégée.
- Soumission de projets : fichier + titre + description.
- Historique par utilisateur avec horodatage.
- Espace privé par groupe.
- Validation/commentaire des enseignants.
- Journalisation des actions sensibles.
- Accès restreint selon les rôles (étudiant, enseignant, admin).

## Architecture des rôles

| Rôle        | Fonctionnalités principales                          |
|-------------|------------------------------------------------------|
| Étudiant    | Déposer projets, consulter l’historique              |
| Enseignant  | Valider/commenter/refuser les projets assignés       |
| Admin       | Créer comptes, gérer promotions, assigner enseignants|

## Structure du projet

```

SecuTrack/
│
├── app/                     # Code principal (Flask)
│   ├── templates/           # Fichiers HTML
│   ├── static/              # CSS, JS, images
│   ├── routes.py            # Définition des routes
│   ├── models.py            # Modèles SQLAlchemy
│   └── utils/               # Fonctions utilitaires (hash, crypto...)
│
├── config.py                # Configuration de l’application
├── requirements.txt         # Dépendances Python
├── README.md                # Fichier d’explication (ce document)
└── run.py                   # Point d’entrée de l’application

```

## Plan de développement

- Sessions hebdomadaires de développement personnel.
- Bilans réguliers pour tester et corriger les fonctionnalités.
- Développement 100% personnalisé sans frameworks automatisés.

## Sécurité intégrée (5 piliers)

- **Authentification** : par session et mot de passe haché
- **Autorisation** : contrôle d’accès par rôle
- **Confidentialité** : chiffrement des fichiers
- **Intégrité** : hachage et vérification des fichiers
- **Audit** : journalisation complète des événements sensibles

##  Auteur

**Ndeye Manar SAMB**  
Étudiante en 2e année DIC - Génie Informatique  
École Supérieure Polytechnique de Dakar  
📧 ndeyemanarsamb@esp.sn

---
