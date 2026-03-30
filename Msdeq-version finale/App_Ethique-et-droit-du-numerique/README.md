# Système IA — ENSA Béni Mellal
## Application Web Flask — Conforme RGPD
**Module : Éthique et Droit du Numérique | Filière : IA & Cybersécurité**

---

## Structure du projet

```
flask_app/
├── app.py                  ← Application principale Flask
├── requirements.txt        ← Dépendances Python
├── ensa_ia.db              ← Base de données SQLite (créée automatiquement)
├── static/
│   ├── css/style.css       ← Feuille de style
│   └── js/main.js          ← JavaScript
└── templates/
    ├── base.html           ← Template de base (navbar, footer)
    ├── login.html          ← Page de connexion
    ├── register.html       ← Page d'inscription
    ├── dashboard.html      ← Tableau de bord
    ├── ask.html            ← Formulaire de demande IA
    ├── history.html        ← Historique des demandes
    └── droits.html         ← Exercice des droits RGPD
```

---

## Installation et lancement

### 1. Prérequis
- Python 3.8 ou supérieur
- pip

### 2. Installer les dépendances
```bash
pip install -r requirements.txt
```

### 3. Lancer l'application
```bash
python app.py
```

### 4. Accéder à l'application
Ouvrez votre navigateur sur : **http://localhost:5000**

**Compte démo :** identifiant `demo` / mot de passe `demo1234`

---

## Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Authentification | Connexion sécurisée avec hachage SHA-256 |
| Inscription | Création de compte utilisateur |
| Demande IA | Question ou résumé de texte |
| Détection PII | Blocage automatique des données personnelles |
| Historique | Consultation et suppression des demandes |
| Droits RGPD | Formulaire d'exercice des droits |
| Journalisation | Audit log de toutes les actions |
| Sessions | Expiration automatique après 2h |

---

## Conformité RGPD

- **Base légale :** Intérêt légitime (art. 6.1.f)
- **Données collectées :** Identifiants anonymisés + métadonnées uniquement
- **Durée de conservation :** 30 jours (configurable)
- **Droits garantis :** Accès, rectification, effacement, opposition, portabilité
- **DPO :** dpo@ensa-bm.ac.ma

---

## Notes de sécurité (production)

En environnement de production :
1. Changer `app.secret_key` par une valeur aléatoire sécurisée
2. Activer HTTPS (TLS)
3. Remplacer SQLite par PostgreSQL/MySQL pour une charge importante
4. Désactiver `debug=True`
5. Configurer les en-têtes HTTP de sécurité (CSP, HSTS)
