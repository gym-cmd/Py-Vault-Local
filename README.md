🛡️ Py-Vault
&lt;div align="center">

    .-------.
   /   _   _   \
  |   |_| |_|   |
  |     ___     |
  |    |___|    |
   \   /   \   /
    '-------'
A secure, local-first, command-line password manager built with Python.

Your digital life, sealed in your own private vault.




&lt;/div>

Py-Vault is a robust password manager that runs directly in your terminal. It provides a secure, offline-first solution to store, manage, and generate your sensitive credentials without relying on third-party cloud services. You control your data completely.

✨ Features
🔒 Strong Encryption: Utilizes Fernet (AES-256-GCM) for authenticated symmetric encryption. Your data is encrypted and authenticated at every step.
🔑 Secure Key Derivation: Your master password is never stored. It's combined with a unique salt and processed through PBKDF2HMAC with 600,000 iterations to derive the encryption key, providing excellent protection against brute-force attacks.
🔎 Data Integrity: All vault files, including backups, are sealed with an HMAC signature. The application will refuse to load any file that has been modified, protecting you from data corruption or tampering.
🎲 Secure Password Generator: Includes a built-in password generator using Python's secrets module to create cryptographically strong random passwords.
⏱️ Auto-Clipboard Clearing: Automatically clears passwords from your system clipboard after a 2-minute delay to prevent accidental exposure.
📦 Portable & Secure Backup: Features a clear, secure process for creating a recovery kit to restore your vault on a new machine.
🧯 Automatic Safety Net: Keeps a rolling history of the last 10 versions of your vault as an automatic safety net, protecting you against accidental data loss.
🛡️ Security Model
Your vault's security is built on a layered model where you hold the keys.

The Master Password (Your Secret): This is the password you memorize and the primary key to your vault. It is never stored on disk.
The Salt File (salt.bin): This is a random, unique "serial number" for your vault. It is not a secret, but it is essential for deriving the correct encryption key from your master password.
The Encryption Key: The final key used to encrypt/decrypt data is created by combining your Master Password and the salt.bin file.
To unlock your data, the application needs both your master password and the matching salt.bin file. This is why the salt.bin is a critical part of your recovery kit when moving to a new computer.

🚀 Getting Started
Prerequisites
Python 3.8 or newer
pip (Python package installer)
Installation
Clone or Download
Get the project files (main.py, requirements.txt) and place them in a dedicated folder. Navigate into that folder in your terminal.

Create a Virtual Environment
It is highly recommended to use a virtual environment to keep project dependencies isolated.

Bash

python -m venv venv
Activate the Virtual Environment

On Windows:
Bash

venv\Scripts\activate
On macOS & Linux:
Bash

source venv/bin/activate
(Your terminal prompt should now change to show (venv))

Install Dependencies
With the virtual environment active, install all the required libraries from the requirements.txt file.

Bash

pip install -r requirements.txt
▶️ How to Use
First-Time Setup
Make sure your virtual environment is active.
Run the application:
Bash

python main.py
The application will guide you through creating a strong master password. Choose a password you will not forget, as it is unrecoverable.
After setup, the application will have created your local vault files: master.key, salt.bin, and vault.json.
Main Menu
Option	Description
[1] Add Password	Save a new credential. You can provide a password or have one generated.
[2] View Passwords	List all saved services and view the details for a specific entry.
[3] Generate Password	Create a strong, random password without saving it to the vault.
[4] Delete Password	Permanently remove a credential from the vault.
[5] Create Recovery Backup	Create a secure, portable backup file for moving your vault.
[6] Restore from Backup	Import a vault from a recovery backup file.
[0] Lock Vault & Exit	Securely exit the application.

Export to Sheets
🔄 Backup and Restore on a New Machine
This is the most critical process to understand. To securely move your vault, you must transfer both the encrypted data and the unique salt file.

Step 1: On Your OLD Computer (Create the Recovery Kit)
Run the application (python main.py) and log in.

Choose option [5] Create Recovery Backup.

The application will create vault_recovery.json and display a critical message with instructions.

Locate the TWO required files for your recovery kit:

vault_recovery.json
salt.bin
Securely copy both files to a portable medium (e.g., an encrypted USB drive).

OLD_COMPUTER/
├── main.py
├── master.key
├── salt.bin              <-- COPY THIS FILE
├── vault.json
└── vault_recovery.json   <-- AND COPY THIS FILE
Step 2: On Your NEW Computer (Restore the Vault)
Create a new, empty folder.
Place the necessary files into this new folder:
Your main.py script.
The requirements.txt file.
The vault_recovery.json file from your recovery kit.
The salt.bin file from your recovery kit.
Follow the Installation steps above (create/activate venv, pip install -r requirements.txt).
Run the application (python main.py).
It will initiate the "First-time setup." This is normal. Enter your original Master Password.
Once at the main menu, choose option [6] Restore from Backup and provide the vault_recovery.json filename.
Your vault is now fully restored and ready to use on the new machine.

📦 Creating an Executable
You can package this application into a single executable file using PyInstaller.

Install PyInstaller:
Bash

pip install pyinstaller
Build the Executable:
Bash

pyinstaller --onefile --name PyVault main.py
Your PyVault.exe (or PyVault on Mac/Linux) will be in the dist folder. Remember that it still needs the vault.json, master.key, and salt.bin files in the same directory to function.
📜 License
This project is licensed under the MIT License. See the LICENSE file for details.