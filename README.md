# 🔐 Local Password Manager

A lightweight, completely offline, and portable password manager built with Python and Tkinter. This application allows users to generate secure, customizable passwords and save them to a local SQLite database that stays hidden securely on your machine.

## ✨ Features

* **Advanced Password Generator:** Create cryptographically secure passwords using custom lengths (8-64 characters) and specific character pools (Uppercase, Lowercase, Numbers, Symbols).
* **Fully Offline & Local:** No cloud sync, no accounts, no subscriptions. Your data never leaves your computer.
* **Hidden SQLite Database:** Automatically creates and manages a `.db` file in the hidden Windows `AppData` folder to keep your desktop clean.
* **Tabbed Interface:** Seamlessly switch between the Generator/Save tool and your Saved Passwords Vault.
* **Real-Time Search:** Instantly filter your saved passwords by Website or Username.
* **Context Menu Management:** Right-click any saved entry in your vault to easily Edit or Delete it.
* **Standalone Executable:** Can be easily compiled into a single `.exe` file for portability.

## 🛠️ Built With

* **Python 3**
* **Tkinter** (Native GUI library)
* **SQLite3** (Built-in database engine)
* **Secrets Module** (For cryptographically strong random numbers)

## 🚀 Getting Started

### Prerequisites
If you want to run the raw Python script or compile it yourself, you will need Python installed on your system.

### Running the Script
1. Clone the repository:
   ```bash
   git clone [https://github.com/MustyKaradag/local-password-manager.git](https://github.com/MustyKaradag/local-password-manager.git)


Navigate to the directory:

```bash
cd local-password-manager
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
Compile the application (hides the console window and bundles everything into one file):
```

```Bash
pyinstaller --onefile --windowed manager.py
Find your standalone app inside the newly created dist folder!
```

📂 Where is my data stored?
To prevent cluttering the directory where the .exe is located, the SQLite database (passwords.db) is automatically generated and stored in your hidden AppData folder:

```Windows Path: C:\Users\<YourUsername>\AppData\Roaming\LocalPasswordManager\passwords.db```

⚠️ Security Disclaimer
This is a local, open-source project designed for ease of use and local control. While the password generation uses cryptographically secure methods, the underlying SQLite database is currently stored as plain text on your local machine. Ensure your Windows user account is secure, and avoid putting the database on shared computers.


```### Step 2: Upload to GitHub

If you already have a GitHub account and Git installed, you can publish your project by following these steps in your command prompt (make sure you are inside your project folder):
```

1. Initialize the repository:
   ```bash
   git init
Add your Python file and your new README file:

Bash
git add manager.py README.md
Commit your files:

Bash
git commit -m "Initial commit: Added password manager script and README"
Go to GitHub.com, click the + icon in the top right, and select New repository. Name it local-password-manager and click Create repository.

Copy the commands GitHub gives you under "…or push an existing repository from the command line". It will look something like this:

Bash
git remote add origin https://github.com/YourUsername/local-password-manager.git
git branch -M main
git push -u origin main
