# 🔐 Local Password Manager v1.3

A lightweight, completely offline, and portable password manager built with Python and Tkinter. This application allows users to generate secure, customizable passwords and save them to a local SQLite database that stays hidden securely on your machine, protected by field-level encryption.

## ✨ Features

* **Advanced Password Generator:** Create cryptographically secure passwords using custom lengths (8-64 characters) and specific character pools.
* **Field-Level Encryption:** Your passwords are mathematically scrambled using `cryptography` (Fernet) before ever touching the database. You need your Master Password to read them.
* **Fully Offline & Local:** No cloud sync, no accounts. Your data never leaves your computer.
* **Hidden SQLite Database:** Automatically creates and manages a `.db` file in the hidden Windows `AppData` folder to keep your desktop clean.
* **Tabbed Interface:** Seamlessly switch between the Generator, your Vault, Backup tools, and About info.
* **Real-Time Search & Management:** Instantly filter your saved passwords. Right-click to edit/delete, or double-click to view details.
* **Quick Copy:** Dedicated buttons to instantly copy your usernames and passwords to your clipboard.
* **Secure Export / Import:** Backup your entire vault to an encrypted `.vault` file with a dedicated backup password, making it easy to restore or move to another PC.
* **Standalone Executable:** Can be easily compiled into a single `.exe` file for portability.

## 🛠️ Built With

* **Python 3**
* **Tkinter** (Native GUI library)
* **SQLite3** (Built-in database engine)
* **Cryptography** (For Fernet encryption & key derivation)
* **Secrets Module** (For cryptographically strong random numbers)

## 🚀 Getting Started

### Prerequisites
If you want to run the raw Python script, you will need Python installed along with the required libraries.

1. Clone the repository:
   ```bash
   git clone [https://github.com/MustyKaradag/local-password-manager.git](https://github.com/MustyKaradag/local-password-manager.git)


2. Navigate to the directory:

```bash
cd local-password-manager
```
3. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```

Run the app:

```bash
python manager.py
```

📦 Compiling to a Portable .exe (Windows)

You can turn this script into a standalone .exe file that runs on Windows machines without needing Python installed.

Install PyInstaller:

```Bash
pip install pyinstaller
```

Compile the application:

```Bash
pyinstaller --onefile --windowed manager.py
```

Find your standalone app inside the newly created dist folder!


📂 Where is my data stored?
To prevent cluttering the directory where the .exe is located, the SQLite database (passwords.db) is automatically generated and stored in your hidden AppData folder:

```Windows Path: C:\Users\<YourUsername>\AppData\Roaming\LocalPasswordManager\passwords.db```

⚠️ Security Disclaimer
This is a local, open-source project designed for ease of use and local control. While the password generation uses cryptographically secure methods, the underlying SQLite database is currently stored as plain text on your local machine. Ensure your Windows user account is secure, and avoid putting the database on shared computers.
