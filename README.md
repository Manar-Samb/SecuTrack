# SecuTrack - Plateforme Sécurisée de Gestion des Projets Étudiants

## 📋 Description

SecuTrack est une plateforme web sécurisée développée avec Python/Flask pour la gestion des projets étudiants dans un environnement académique. Elle permet aux étudiants de soumettre leurs projets, aux enseignants de les évaluer, et aux administrateurs de gérer les utilisateurs et groupes.

## 🔐 Caractéristiques de Sécurité

### Les 5 Piliers de Sécurité Implémentés

1. **Authentification** - Mots de passe hachés avec Werkzeug + sessions sécurisées
2. **Autorisation** - Contrôle d'accès basé sur les rôles (RBAC)
3. **Audit** - Journalisation complète des actions sensibles
4. **Confidentialité** - Chiffrement AES-256 des fichiers soumis
5. **Intégrité** - Hachage SHA-256 et validation des fichiers

### Fonctionnalités de Sécurité

- ✅ Hachage sécurisé des mots de passe (Werkzeug)
- ✅ Sessions chiffrées avec expiration automatique
- ✅ Chiffrement des fichiers avec AES-256
- ✅ Validation d'intégrité par hachage SHA-256
- ✅ Contrôle d'accès granulaire par rôle
- ✅ Audit trail complet avec horodatage
- ✅ Protection contre les injections SQL (requêtes préparées)
- ✅ Validation et sanitisation des entrées
- ✅ Gestion sécurisée des fichiers uploadés

## 👥 Rôles Utilisateurs

### 🎓 Étudiant
- Soumettre des projets (fichier + métadonnées)
- Consulter l'historique de son groupe
- Suivre le statut de ses soumissions
- Changer son mot de passe

### 👨‍🏫 Enseignant
- Évaluer les projets assignés
- Approuver/rejeter les soumissions
- Commenter les travaux
- Consulter les statistiques de ses groupes

### 👨‍💼 Administrateur
- Créer et gérer les comptes utilisateurs
- Créer et gérer les groupes
- Assigner les enseignants aux groupes
- Consulter les logs d'audit
- Gérer les permissions système

## 🛠️ Technologies Utilisées

- **Backend**: Python 3.8+ avec Flask
- **Base de données**: MySQL 8.0+
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Sécurité**: 
  - `werkzeug.security` pour le hachage des mots de passe
  - `PyCryptodome` pour le chiffrement AES
  - `cryptography` pour les opérations cryptographiques
- **Autres**: PyMySQL, python-dotenv

## 📦 Installation

### Prérequis

1. Python 3.8 ou supérieur
2. MySQL 8.0 ou supérieur
3. pip (gestionnaire de paquets Python)

### Étapes d'installation

1. **Cloner le projet**
```bash
git clone https://github.com/manar-vi/SecuTrack.git
cd SecuTrack
```

2. **Installer les dépendances**
```bash
pip install -r requirements.txt
```

3. **Configurer la base de données**
   - Créer une base de données MySQL
   - Modifier le fichier `.env` avec vos paramètres de connexion

4. **Initialiser la base de données**
```bash
python setup_database.py
```

5. **Lancer l'application**
```bash
python app.py
```

L'application sera accessible à l'adresse : `http://127.0.0.1:5000`

## ⚙️ Configuration

### Variables d'environnement (.env)

```env
# Base de données
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=votre_mot_de_passe
DB_NAME=secutrackdb

# Sécurité
SECRET_KEY=votre_clé_secrète_très_longue_et_complexe
ENCRYPTION_KEY=clé_de_chiffrement_32_bytes_en_hex

# Upload
MAX_FILE_SIZE=16777216
UPLOAD_FOLDER=uploads
```

### Structure de la base de données

- `users` - Informations des utilisateurs et authentification
- `groups` - Groupes d'étudiants avec enseignants assignés
- `projects` - Projets soumis avec métadonnées et fichiers chiffrés
- `audit_logs` - Journal d'audit de toutes les actions
- `user_sessions` - Gestion sécurisée des sessions

## 🔑 Comptes par défaut

Après l'installation, les comptes suivants sont créés :

| Rôle | Nom d'utilisateur | Mot de passe |
|------|------------------|--------------|
| Administrateur | `admin` | `admin123` |
| Enseignant | `teacher` | `teacher123` |
| Étudiant | `student` | `student123` |

⚠️ **Important** : Changez ces mots de passe par défaut en production !

## 📁 Structure du projet

```
SecuTrack/
├── app.py                 # Application Flask principale
├── setup_database.py     # Script d'initialisation de la BDD
├── requirements.txt       # Dépendances Python
├── .env                  # Variables d'environnement
├── README.md             # Documentation
├── templates/            # Templates HTML
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── student_dashboard.html
│   ├── teacher_dashboard.html
│   ├── admin_dashboard.html
│   ├── submit_project.html
│   └── change_password.html
├── uploads/              # Fichiers chiffrés (créé automatiquement)
└── secutrack.log         # Fichier de logs (créé automatiquement)
```

## 🚀 Utilisation

### Pour les étudiants
1. Se connecter avec ses identifiants
2. Accéder au tableau de bord étudiant
3. Soumettre un projet via "Soumettre un projet"
4. Suivre le statut dans l'historique

### Pour les enseignants
1. Se connecter avec ses identifiants
2. Consulter les projets en attente d'évaluation
3. Approuver/rejeter avec commentaires
4. Suivre les statistiques de ses groupes

### Pour les administrateurs
1. Se connecter avec ses identifiants
2. Créer des utilisateurs et groupes
3. Assigner les enseignants aux groupes
4. Consulter les logs d'audit système

## 🔒 Sécurité en Production

### Recommandations importantes

1. **Changez toutes les clés par défaut** dans `.env`
2. **Utilisez HTTPS** en production
3. **Configurez un firewall** approprié
4. **Sauvegardez régulièrement** la base de données
5. **Surveillez les logs** d'audit
6. **Mettez à jour** les dépendances régulièrement

### Audit et Monitoring

- Tous les événements sensibles sont loggés
- Les tentatives de connexion sont auditées
- Les actions sur les projets sont tracées
- Les modifications de comptes sont enregistrées

## 🧪 Tests

### Tests de sécurité recommandés

1. **Test d'authentification**
   - Tentatives de connexion avec des identifiants invalides
   - Vérification de l'expiration des sessions

2. **Test d'autorisation**
   - Accès aux ressources selon les rôles
   - Tentatives d'escalade de privilèges

3. **Test d'intégrité**
   - Vérification des hachages de fichiers
   - Validation du chiffrement/déchiffrement

4. **Test d'audit**
   - Vérification de l'enregistrement des actions
   - Intégrité des logs d'audit

## 📝 Développement

### Approche DevSecOps

Ce projet suit une approche DevSecOps avec :
- Sécurité intégrée dès la conception
- Code documenté et commenté
- Validation des entrées à tous les niveaux
- Gestion d'erreurs robuste
- Logging complet pour l'audit

### Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit les changements (`git commit -m 'Add AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📄 Licence

Ce projet est développé dans un cadre académique pour l'apprentissage de la programmation sécurisée.

## 👨‍💻 Auteur

**Ndeye Manar SAMB**
- Email: ndeyemanarsamb@esp.sn
- GitHub: [@manar-vi](https://github.com/manar-vi)

## 🆘 Support

Pour toute question ou problème :
1. Consultez la documentation
2. Vérifiez les logs d'erreur
3. Contactez l'auteur par email

---

*SecuTrack - Sécurisé par design, développé avec ❤️ pour l'éducation*
