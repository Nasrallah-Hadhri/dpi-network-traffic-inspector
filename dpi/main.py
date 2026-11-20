import os
import secrets

from database import Database
from ui import UI
from controller import Controller


def initialize_app():
    db = Database()
    # Create the initial admin account if it does not exist yet.
    # Credentials come from the environment (see .env.example); nothing is hard-coded.
    admin_user = os.environ.get("DPI_ADMIN_USERNAME", "admin")
    if not db.get_user(admin_user):
        admin_password = os.environ.get("DPI_ADMIN_PASSWORD")
        if admin_password:
            db.add_user(admin_user, admin_password, "ADMIN")
            print(f"Initial admin user '{admin_user}' created from DPI_ADMIN_PASSWORD.")
        else:
            admin_password = secrets.token_urlsafe(12)
            db.add_user(admin_user, admin_password, "ADMIN")
            print(f"Initial admin user '{admin_user}' created with a random one-time password: {admin_password}")
            print("Store it now (it is not saved anywhere else), or set DPI_ADMIN_PASSWORD before the first run.")
    db.close()

    # Initialize UI and Controller
    root = UI(None) # Pass None for now, will set controller later
    controller = Controller(root)
    root.controller = controller # Set the controller for the UI

    root.mainloop()

if __name__ == "__main__":
    initialize_app()
    print("Application started.")
