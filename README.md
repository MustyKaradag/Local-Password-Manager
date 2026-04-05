# 🔐 Local Password Manager v1.6

A lightweight, completely offline, and portable password manager built with Python and Tkinter. This application allows users to generate secure, customizable passwords and save them to a local SQLite database that stays hidden securely on your machine, protected by field-level encryption. 

## ✨ Core Features
* **Field-Level Encryption:** Your passwords are mathematically scrambled using `cryptography` (Fernet) before ever touching the database. You need your Master Password to read them.
* **Fully Offline & Local:** No cloud sync, no accounts. Your data never leaves your computer.
* **Hidden SQLite Database:** Automatically creates and manages a `.db` file in the hidden Windows `AppData` folder to keep your desktop clean.
* **Quick Copy:** Dedicated buttons to instantly copy your usernames and passwords to your clipboard (requires Master Password verification for saved passwords).
* **Secure Export / Import:** Backup your entire vault to an encrypted `.vault` file with a dedicated backup password, making it easy to restore or move to another PC.
* **Standalone Executable:** Can be easily compiled into a single `.exe` file for portability.
* * **CSV Migration:** Instantly import and encrypt standard `.csv` exports from Google Chrome, LastPass, or other password managers.
* **Auto-Lock Security:** The vault automatically locks and hides itself after 2 minutes of inactivity, requiring your Master Password to reopen.
* **Clipboard Auto-Clear:** Wipes your clipboard 30 seconds after copying a password to prevent accidental pasting.
* **Password Strength Meter:** Real-time visual feedback on the strength of your generated passwords.
* **Multi-Language Support:** UI translations available in English, Turkish, Polish, Spanish, Italian, Portuguese, and German.

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

📂 Where is my data stored?
To prevent cluttering the directory where the .exe is located, the SQLite database (passwords.db) is automatically generated and stored in your hidden AppData folder:

```Windows Path: C:\Users\<YourUsername>\AppData\Roaming\LocalPasswordManager\passwords.db```

or
to use in cmd
```
%APPDATA%\LocalPasswordManager
```

🛡️ Windows SmartScreen Warning
Because this is a newly compiled, open-source application and not signed by a costly corporate certificate, Windows Defender SmartScreen may flag it as an "unrecognized app" the first time you run it.

To run the app:

1. Click More info on the blue warning screen.

2. Click the Run anyway button.

Note: You can verify the security of this app by reading the open-source Python code provided in this repository before downloading the .exe.

⚠️ Security Note
This is a local, open-source project designed for ease of use and local control. While the passwords are encrypted using Fernet (AES), the database itself remains local to your machine. Do not lose your Master Password, or you will permanently lose access to your vault!
