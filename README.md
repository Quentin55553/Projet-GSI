



## 🛠️ **Description**

Cette branche constitue l'un des deux rendus.  

Il contient des tests de fonctions qui simulent une partie du Signal Protocol. Le code que nous avons produit est entièrement commenté, voici les fichiers principaux à regarder :  

- chat/crypto.py  
- chat/models.py  
- chat/tests.py  

Ne pas faire attention à l'application sous-jacente sur ce projet Django, seuls comptent les tests dans ce dossier, ils servent de "preuve de concept" pour l'implémentation d'une communication sécurisée. Nous avions au départ prévu de reprendre l'application en l'améliorant, mais nous avons finalement créé notre propre interface disponible sur l'autre branche de ce dépôt.  

---

## 🖥️ **Accès au projet**


1. **Télécharger le dépôt**

   ```bash
   git clone https://github.com/Quentin55553/Projet-GSI.git
   cd Projet-GSI
   ```

2. **Changer de branche**

   ```bash
   git checkout Protocole
   ```

3. **Installer les dépendances**

   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Initialiser la BDD**

   ```bash
   python manage.py makemigrations  
   python manage.py migrate
   ```

5. **Définir la variable d'environnement**

   ```bash
   export DJANGO_SETTINGS_MODULE=devnoms.settings
   ```

6. **Effectuer les tests**

	```bash
   python manage.py test
   ```

