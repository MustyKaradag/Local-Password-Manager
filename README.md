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
   git clone [https://github.com/yourusername/local-password-manager.git](https://github.com/yourusername/local-password-manager.git)
