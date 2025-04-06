## 🛠️ **Technology Stack**

- **Backend**: Django (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Database**: PostgreSQL
- **Real-Time Communication**: WebSockets (for real-time communication)

---

## 🖥️ **Travailler sur le projet**


1. **Télécharger le dépôt**

   ```bash
   git clone https://github.com/Quentin55553/Projet-GSI.git
   cd Projet-GSI
   ```

2. **Changer de branche**

   ```bash
   git checkout Implémentation
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

6. **Lancer le serveur**

   ```bash
   daphne devnoms.asgi:application
   ```

7. Aller à l'adresse : `http://localhost:8000/`.

---

## 📷 **Screenshots**

Voici un aperçu de l'application **Devnoms Chat** :

**Page de connexion**  
![Login](https://filesstatic.netlify.app/Chatapp/img/login.png)

**Page d'inscription**  
![Signup](https://filesstatic.netlify.app/Chatapp/img/signup.png)

**Interface de discussion**  
![Chat Interface](https://filesstatic.netlify.app/Chatapp/img/chat.png)

**Gestion du profil**  
![Edit Profile](https://filesstatic.netlify.app/Chatapp/img/edit.png)
