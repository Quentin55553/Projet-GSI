## 📋 **Description**

Cette branche constitue l'un des deux rendus.  

Il contient la base visuelle de l'interface de l'application.

Celle-ci n'intègre pas encore les protocoles, situés sur l'autre branche de ce projet, mais elle est représentative de l'apparence finale de l'application.

---

## 🖥️ **Accès au projet**


1. **Se placer à la racine du projet (là où est ce readme)**

2. **Créer et activer l'environnement virtuel**

    ```bash
    python -m venv venv
    source venv/bin/activate
    ```

3. **Installer Django**

    ```bash
    pip install Django==4.2
    ```

> [!NOTE]
> Le bon fonctionnement de l'interface n'est pas garanti avec une version de Django supérieure ou égale à 5.0.

4. **Initialiser la base de données**

    ```bash
    python manage.py makemigrations  
    python manage.py migrate
    ```

5. **Lancer le serveur**

    ```bash
    python manage.py runserver
    ```

6. **Accéder à l'interface**

    Ouvrez votre navigateter à l'adresse : [http://localhost:8000](http://localhost:8000)
