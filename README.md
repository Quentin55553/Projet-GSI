## 📋 **Description**

Cette branche constitue l'un des deux rendus.  

Il contient des tests de fonctions qui simulent une partie du Signal Protocol. Le code que nous avons produit est entièrement commenté, voici les fichiers principaux à regarder :  

- chat/crypto.py  
- chat/models.py  
- chat/tests.py  

Ne pas faire attention à l'application sous-jacente sur ce projet Django, seuls comptent les tests dans ce dossier, ils servent de "preuve de concept" pour l'implémentation d'une communication sécurisée. Nous avions au départ prévu de reprendre l'application en l'améliorant, mais nous avons finalement créé notre propre interface disponible sur l'autre branche de ce dépôt.  

---

## 🖥️ **Accès au projet**


1. **Se placer à la racine du projet (là où est ce readme)**

2. **Installer les dépendances**

   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Initialiser la BDD**

   ```bash
   python manage.py makemigrations  
   python manage.py migrate
   ```

4. **Définir la variable d'environnement**

   ```bash
   export DJANGO_SETTINGS_MODULE=devnoms.settings
   ```

5. **Effectuer les tests**

   ```bash
   python manage.py test
   ```
   
