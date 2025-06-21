# main.py - Py-Vault: A Secure Command-Line Password Vault
import os
import json
import string
import random
import time
import threading
import hashlib
import base64
import hmac
import pyperclip
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from termcolor import colored
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
class Config:
    """Groups all configuration constants for easy management."""
    VAULT_FILE = "vault.json"
    MASTER_FILE = "master.key"
    SALT_FILE = "salt.bin"
    BACKUP_DIR = "vault_backups"
    CLIPBOARD_CLEAR_DELAY = 120
    KDF_ITERATIONS = 600_000
    MAX_LOGIN_ATTEMPTS = 5
    MAX_BACKUPS = 10
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_MAX_LENGTH = 128
    PASSWORD_DEFAULT_LENGTH = 16

class AsciiArt:
    """Container for colored ASCII art elements and messages."""
    PROMPT = colored("[~] ", 'cyan')

    @staticmethod
    def SUCCESS(text: str) -> str:
        return colored(f"[+] {text}", 'green', attrs=['bold'])

    @staticmethod
    def ERROR(text: str) -> str:
        return colored(f"[-] {text}", 'red', attrs=['bold'])

    @staticmethod
    def INFO(text: str) -> str:
        return colored(f"[*] {text}", 'blue')

    @staticmethod
    def WARNING(text: str) -> str:
        return colored(f"[!] {text}", 'yellow', attrs=['bold'])

# --- Logging Helper Functions ---
def log_success(message: str):
    """Prints a success message in a standard format."""
    print(AsciiArt.SUCCESS(message))

def log_error(message: str):
    """Prints an error message in a standard format."""
    print(AsciiArt.ERROR(message))

def log_info(message: str):
    """Prints an info message in a standard format."""
    print(AsciiArt.INFO(message))

def log_warning(message: str):
    """Prints a warning message in a standard format."""
    print(AsciiArt.WARNING(message))


# --- Main Application Class ---
class PasswordVault:
    def __init__(self):
        self.salt = self._get_or_create_salt()
        self.fernet = None
        self.hmac_key = None
        self._ensure_backup_dir()

    def _ensure_backup_dir(self):
        if not os.path.exists(Config.BACKUP_DIR):
            os.makedirs(Config.BACKUP_DIR)

    def _get_or_create_salt(self) -> bytes:
        if not os.path.exists(Config.SALT_FILE):
            salt = os.urandom(32)
            with open(Config.SALT_FILE, "wb") as f:
                f.write(salt)
            return salt
        with open(Config.SALT_FILE, "rb") as f:
            return f.read()

    def _derive_key(self, master_password: str, salt_modifier: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt + salt_modifier,
            iterations=Config.KDF_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(master_password.encode())

    def _initialize_keys(self, master_password: str):
        encryption_key_raw = self._derive_key(master_password, b"_encryption_key_")
        self.fernet = Fernet(base64.urlsafe_b64encode(encryption_key_raw))
        self.hmac_key = self._derive_key(master_password, b"_hmac_key_")

    def _calculate_hmac(self, data: dict) -> str:
        clean_data = {k: v for k, v in data.items() if k != "_hmac"}
        vault_bytes = json.dumps(clean_data, sort_keys=True).encode()
        return hmac.new(self.hmac_key, vault_bytes, hashlib.sha256).hexdigest()

    def _hash_master_password(self, password: str) -> bytes:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

    def _verify_master_password(self, password: str, hashed: bytes) -> bool:
        return bcrypt.checkpw(password.encode(), hashed)

    def _setup_new_master_password(self) -> str:
        log_info("First-time setup: Create your master password.")
        log_warning("Choose a strong, memorable password. It cannot be recovered!")
        while True:
            pw1 = getpass(AsciiArt.PROMPT + "Set master password: ")
            if len(pw1) < Config.PASSWORD_MIN_LENGTH:
                log_error(f"Password must be at least {Config.PASSWORD_MIN_LENGTH} characters long.")
                continue
            pw2 = getpass(AsciiArt.PROMPT + "Confirm password: ")
            if pw1 == pw2:
                hashed_pw = self._hash_master_password(pw1)
                with open(Config.MASTER_FILE, "wb") as f:
                    f.write(hashed_pw)
                log_success("Master password set successfully.")
                return pw1
            log_error("Passwords do not match. Please try again.")

    def _login(self) -> str:
        try:
            with open(Config.MASTER_FILE, "rb") as f:
                stored_hash = f.read()
        except FileNotFoundError:
            return self._setup_new_master_password()
        for attempt in range(Config.MAX_LOGIN_ATTEMPTS):
            prompt = f"Enter master password (Attempt {attempt + 1}/{Config.MAX_LOGIN_ATTEMPTS}): "
            pw = getpass(AsciiArt.PROMPT + prompt)
            if self._verify_master_password(pw, stored_hash):
                return pw
            log_error("Incorrect password.")
        log_warning("Too many failed attempts. Exiting for security.")
        exit(1)

    def save_vault(self, data: dict):
        self._create_backup(data)
        data_to_save = data.copy()
        data_to_save["_hmac"] = self._calculate_hmac(data_to_save)
        try:
            with open(Config.VAULT_FILE, "w") as f:
                json.dump(data_to_save, f, indent=4)
        except IOError as e:
            log_error(f"Could not write to vault file: {e}")

    def load_vault(self) -> dict:
        if not os.path.exists(Config.VAULT_FILE):
            return {}
        try:
            with open(Config.VAULT_FILE, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            log_error("Vault file is corrupted or unreadable.")
            return self._handle_corrupted_vault()
        stored_hmac = data.pop("_hmac", None)
        if not stored_hmac:
            log_warning("Vault integrity could not be verified (old format or corrupted).")
            return data
        expected_hmac = self._calculate_hmac(data)
        if not hmac.compare_digest(stored_hmac, expected_hmac):
            log_error("Vault integrity check failed! The vault may have been tampered with.")
            return self._handle_corrupted_vault()
        return data
        
    def _create_backup(self, data: dict):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(Config.BACKUP_DIR, f"vault_backup_{timestamp}.json")
        try:
            with open(backup_file, "w") as f:
                json.dump(data, f, indent=4)
            self._cleanup_old_backups()
        except IOError as e:
            log_warning(f"Could not create backup: {e}")

    def _cleanup_old_backups(self):
        try:
            backup_files = sorted([f for f in os.listdir(Config.BACKUP_DIR) if f.startswith("vault_backup_")], reverse=True)
            for old_backup in backup_files[Config.MAX_BACKUPS:]:
                os.remove(os.path.join(Config.BACKUP_DIR, old_backup))
        except (IOError, OSError) as e:
            log_warning(f"Could not clean up old backups: {e}")

    def _restore_from_backup(self) -> dict:
        try:
            backup_files = sorted([os.path.join(Config.BACKUP_DIR, f) for f in os.listdir(Config.BACKUP_DIR) if f.startswith("vault_backup_")], key=os.path.getmtime, reverse=True)
        except FileNotFoundError:
            log_error("Backup directory not found.")
            return {}
        if not backup_files:
            log_error("No valid backups found.")
            return {}
        backup_path = backup_files[0]
        try:
            with open(backup_path, "r") as f:
                data = json.load(f)
            with open(Config.VAULT_FILE, "w") as f:
                json.dump(data, f, indent=4)
            log_success(f"Vault restored from backup: {os.path.basename(backup_path)}")
            return self.load_vault()
        except (json.JSONDecodeError, IOError) as e:
            log_error(f"Error restoring backup: {e}")
            return {}

    def _handle_corrupted_vault(self) -> dict:
        print("\n--- VAULT RECOVERY ---")
        print("[1] Restore from automatic backup")
        print("[2] Restore from a recovery backup file")
        print("[3] Start with a new, empty vault")
        print("[0] Exit")
        while True:
            choice = input(AsciiArt.PROMPT + "Select recovery option: ").strip()
            if choice == "1": return self._restore_from_backup()
            elif choice == "2": return self._import_vault_interactive()
            elif choice == "3":
                confirm = input(AsciiArt.WARNING("This will delete all data. Type 'YES' to confirm: ") + " ")
                if confirm == "YES": return {}
                log_info("Operation cancelled.")
            elif choice == "0" or "exit" or "quit" or "bye" or "q":
                log_info("Exiting.")
                exit(1)
            else: log_error("Invalid option.")

    def _save_entry(self, data: dict, service: str, username: str, password: str):
        try:
            encrypted_password = self.fernet.encrypt(password.encode()).decode()
            data[service] = {"username": username, "password": encrypted_password}
            self.save_vault(data)
            log_success(f"Password saved for '{service}'.")
        except Exception as e:
            log_error(f"Error saving password: {e}")

    def add_password(self, data: dict):
        service = input(AsciiArt.PROMPT + "Enter service name: ").strip()
        if not service:
            log_error("Service name cannot be empty.")
            return
        if service in data:
            log_warning(f"Service '{service}' already exists. Delete it or use a different name.")
            return
        username = input(AsciiArt.PROMPT + "Enter username (optional): ").strip()
        password = getpass(AsciiArt.PROMPT + "Enter password (leave blank to generate): ").strip()
        if not password:
            length, use_symbols, use_numbers = self._get_password_generation_options()
            password = self._generate_password(length, use_symbols, use_numbers)
            log_info(f"Generated password: {password}")
            self._copy_to_clipboard(password)
        self._save_entry(data, service, username, password)

    def generate_standalone_password(self, data: dict):
        length, use_symbols, use_numbers = self._get_password_generation_options()
        password = self._generate_password(length, use_symbols, use_numbers)
        log_info(f"Generated password: {password}")
        self._copy_to_clipboard(password)
        save = input(AsciiArt.PROMPT + "Save this password to the vault? (y/N): ").strip().lower()
        if save == 'y' or "" or "yes":
            service = input(AsciiArt.PROMPT + "Enter service name: ").strip()
            if service:
                username = input(AsciiArt.PROMPT + "Enter username (optional): ").strip()
                self._save_entry(data, service, username, password)
            else:
                log_error("Service name cannot be empty. Password not saved.")

    def delete_password(self, data: dict):
        services = [k for k in data if not k.startswith('_')]
        if not services:
            log_info("No passwords to delete.")
            return
        print("\n" + colored("--- Select Service to Delete ---", 'yellow'))
        for i, service in enumerate(services, 1):
            print(f"[{i}] {service}")
        try:
            choice = input(AsciiArt.PROMPT + "Enter service number: ").strip()
            service_to_delete = services[int(choice) - 1]
            prompt_text = AsciiArt.WARNING(f"Delete '{service_to_delete}'? This is permanent.")
            confirm = input(prompt_text + " (y/N): ").lower()
            if confirm == 'y':
                del data[service_to_delete]
                self.save_vault(data)
                log_success(f"Deleted '{service_to_delete}'.")
            else:
                log_info("Deletion cancelled.")
        except (ValueError, IndexError):
            log_error("Invalid selection.")

    def view_passwords(self, data: dict):
        services = [k for k in data if not k.startswith('_')]
        if not services:
            log_info("Vault is empty. Add a password first.")
            return
        print("\n" + colored("--- Saved Services ---", 'yellow'))
        for i, service in enumerate(services, 1):
            print(f"[{i}] {service}")
        print("[0] Return to main menu")
        try:
            selection = input(AsciiArt.PROMPT + "Select a service to view: ").strip()
            idx = int(selection)
            if idx == 0: return
            service = services[idx - 1]
            entry = data[service]
            password = self.fernet.decrypt(entry["password"].encode()).decode()
            username = entry.get("username", "(not set)")
            border = colored('-'*20, 'magenta')
            print(f"\n{border}")
            print(f" {colored('Service:', 'magenta')}  {service}")
            print(f" {colored('Username:', 'magenta')} {username}")
            print(f" {colored('Password:', 'magenta')} {password}")
            print(border)
            copy = input(AsciiArt.PROMPT + "Copy password to clipboard? (y/N): ").strip().lower()
            if copy == 'y':
                self._copy_to_clipboard(password)
        except (ValueError, IndexError):
            log_error("Invalid selection.")
        except InvalidToken:
            log_error("Could not decrypt this entry. It may be corrupted.")

    def _generate_password(self, length: int, use_symbols: bool, use_numbers: bool) -> str:
        length = max(Config.PASSWORD_MIN_LENGTH, min(Config.PASSWORD_MAX_LENGTH, length))
        chars = list(string.ascii_letters)
        if use_symbols: chars.extend("!@#$%^&*()-_=+[]{};:,.<>?")
        if use_numbers: chars.extend(string.digits)
        password = list()
        if use_symbols: password.append(random.SystemRandom().choice("!@#$%^&*()-_=+[]{};:,.<>?"))
        if use_numbers: password.append(random.SystemRandom().choice(string.digits))
        password.append(random.SystemRandom().choice(string.ascii_lowercase))
        password.append(random.SystemRandom().choice(string.ascii_uppercase))
        remaining_length = length - len(password)
        password.extend(random.SystemRandom().choice(chars) for _ in range(remaining_length))
        random.SystemRandom().shuffle(password)
        return "".join(password)

    def _get_password_generation_options(self) -> tuple[int, bool, bool]:
        try:
            prompt = f"Enter password length ({Config.PASSWORD_MIN_LENGTH}-{Config.PASSWORD_MAX_LENGTH}, default {Config.PASSWORD_DEFAULT_LENGTH}): "
            length_input = input(AsciiArt.PROMPT + prompt).strip()
            length = Config.PASSWORD_DEFAULT_LENGTH if not length_input else int(length_input)
        except ValueError:
            log_warning(f"Invalid length. Using default ({Config.PASSWORD_DEFAULT_LENGTH}).")
            length = Config.PASSWORD_DEFAULT_LENGTH
        symbols = input(AsciiArt.PROMPT + "Include symbols? (Y/n): ").strip().lower() != 'n'
        numbers = input(AsciiArt.PROMPT + "Include numbers? (Y/n): ").strip().lower() != 'n'
        return length, symbols, numbers

    def create_recovery_backup(self, data: dict):
        """Creates an encrypted backup file and gives the user critical instructions."""
        export_data = {k: v for k, v in data.items() if not k.startswith('_')}
        if not export_data:
            log_info("No data to export.")
            return

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        export_file = f"vault_recovery_{timestamp}.json"
        
        try:
            with open(export_file, "w") as f:
                json.dump(export_data, f, indent=4)
            
            # Provide explicit, clear instructions to the user. This is the most important part.
            log_success(f"Recovery backup created: {export_file}")
            print("-" * 60)
            log_warning("To restore this vault on a new computer, you need THREE things:")
            print("  1. This backup file (" + colored(export_file, 'cyan') + ")")
            print("  2. The '" + colored(Config.SALT_FILE, 'cyan') + "' file from this computer's directory.")
            print("  3. Your Master Password.")
            log_info(f"Copy both '{export_file}' AND '{Config.SALT_FILE}' to your new machine for recovery.")
            print("-" * 60)

        except IOError as e:
            log_error(f"Error creating recovery backup: {e}")

    def restore_from_backup(self, data: dict):
        """Guides the user to restore an encrypted vault from a backup file."""
        imported_data = self._import_vault_interactive()
        if not imported_data: 
            return # User cancelled or error occurred

        merge_choice = input(AsciiArt.PROMPT + "Merge with existing data or replace? (merge/replace): ").lower()
        if merge_choice == "replace":
            data.clear()
            data.update(imported_data)
        else: # Default to merge
            conflicts = [s for s in imported_data if s in data]
            for service, entry in imported_data.items():
                if service not in conflicts: data[service] = entry
            
            if conflicts:
                log_warning(f"Conflicts found for: {', '.join(conflicts)}")
                for service in conflicts:
                    overwrite = input(f"{AsciiArt.PROMPT}Overwrite '{service}'? (y/N): ").lower()
                    if overwrite == 'y': data[service] = imported_data[service]

        self.save_vault(data)
        log_success("Restore complete.")

    def _import_vault_interactive(self) -> dict | None:
        """Handles the interactive part of importing a vault file."""
        import_file = input(AsciiArt.PROMPT + "Enter path to recovery backup file: ").strip()
        try:
            with open(import_file, "r") as f:
                imported_data = json.load(f)
            
            if not isinstance(imported_data, dict): raise ValueError("Invalid format.")
            
            # Test decryption on the first entry found to validate the key
            for entry in imported_data.values():
                if isinstance(entry, dict) and "password" in entry:
                    self.fernet.decrypt(entry["password"].encode())
                    break 
            
            log_success(f"Successfully decrypted and loaded {len(imported_data)} entries.")
            return imported_data
        except FileNotFoundError: 
            log_error("File not found.")
        except (json.JSONDecodeError, ValueError): 
            log_error("Invalid or corrupted backup file.")
        except InvalidToken: 
            log_error("Cannot decrypt entries. This is likely due to an incorrect master password OR a mismatched 'salt.bin' file.")
            log_info("Ensure you have the correct 'salt.bin' file from the original machine in the same directory as this script.")
        except Exception as e: 
            log_error(f"An unexpected error occurred during import: {e}")
        return None

    def _clear_clipboard_delayed(self):
        def _clear():
            time.sleep(Config.CLIPBOARD_CLEAR_DELAY)
            pyperclip.copy("")
        threading.Thread(target=_clear, daemon=True).start()

    def _copy_to_clipboard(self, text: str):
        pyperclip.copy(text)
        log_success(f"Copied to clipboard. Will be cleared in {Config.CLIPBOARD_CLEAR_DELAY} seconds.")
        self._clear_clipboard_delayed()

    def _clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def _display_menu(self):
        """Displays the main menu with perfectly aligned columns."""
        print("\n" + colored("--- PY-VAULT MAIN MENU " + "-"*35, 'yellow', attrs=['bold']))
        
        menu_color = 'white'
        
        # Menu items defined here for easy editing and alignment
        menu_items = [
            ("1", "Add Password",          "4", "Delete Password"),
            ("2", "View Passwords",        "5", "Create Recovery Backup"), # Renamed
            ("3", "Generate Password",     "6", "Restore from Backup")      # Renamed
        ]
        
        column_width = max(len(item[1]) for item in menu_items) + 4
        
        for l_num, l_text, r_num, r_text in menu_items:
            left_column = colored(l_text.ljust(column_width), menu_color)
            left_num_c = colored(f'[{l_num}]', 'cyan')
            right_num_c = colored(f'[{r_num}]', 'cyan')
            right_column = colored(r_text, menu_color)
            
            print(f"{left_num_c} {left_column}{right_num_c} {right_column}")
            
        print(f"{colored('[0]', 'cyan')} {colored('Lock Vault & Exit', 'red')}")
        print(colored("-" * 60, 'yellow', attrs=['bold']))

    def run(self):
        self._clear_terminal()
        print(colored("="*60, 'magenta'))
        print(colored("Py-Vault: A Secure Command-Line Password Vault", 'cyan', attrs=['bold']))
        print(colored("="*60, 'magenta'))
        
        master_password = self._login()
        self._initialize_keys(master_password)
        
        try:
            data = self.load_vault()
            log_success("Vault loaded successfully.")
        except Exception as e:
            log_error(f"A critical error occurred while loading the vault: {e}")
            return
            
        while True:
            self._display_menu()
            choice = input(AsciiArt.PROMPT + "Select option: ").strip()
            # Updated actions dictionary with new function names
            actions = {
                "1": self.add_password, 
                "2": self.view_passwords, 
                "3": self.generate_standalone_password, 
                "4": self.delete_password, 
                "5": self.create_recovery_backup, 
                "6": self.restore_from_backup
            }
            if choice == "0":
                log_info("Vault locked. Goodbye!")
                break
            elif choice in actions:
                self._clear_terminal()
                actions[choice](data)
                input("\n" + AsciiArt.PROMPT + "Press Enter to continue...")
                self._clear_terminal()
            else:
                log_error("Invalid option. Please try again.")

def main():
    try:
        vault = PasswordVault()
        vault.run()
    except KeyboardInterrupt:
        print() 
        log_warning("User interrupted. Vault locked. Goodbye!")
    except Exception as e:
        print() 
        log_error(f"An unexpected critical error occurred: {e}")
        log_info("Please report this issue if it persists.")

if __name__ == "__main__":
    main()
